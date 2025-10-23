package wafupdate

import (
	"SamWaf/binarydist"
	"SamWaf/global"
	"SamWaf/utils"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/mod/semver"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	// holds a timestamp which triggers the next update
	upcktimePath = "cktime"                            // path to timestamp file relative to u.Dir
	plat         = runtime.GOOS + "-" + runtime.GOARCH // ex: linux-amd64
)

var (
	ErrHashMismatch = errors.New("new file hash mismatch after patch")

	defaultHTTPRequester = HTTPRequester{}
)

// Updater is the configuration and runtime data for doing an update.
//
// Note that ApiURL, BinURL and DiffURL should have the same value if all files are available at the same location.
//
// Example:
//
//	updater := &selfupdate.Updater{
//		CurrentVersion: version,
//		ApiURL:         "http://updates.yourdomain.com/",
//		BinURL:         "http://updates.yourdownmain.com/",
//		DiffURL:        "http://updates.yourdomain.com/",
//		Dir:            "update/",
//		CmdName:        "myapp", // app name
//	}
//	if updater != nil {
//		go updater.BackgroundRun()
//	}
type Updater struct {
	CurrentVersion string    // Currently running version. `dev` is a special version here and will cause the updater to never update.
	ApiURL         string    // Base URL for API requests (JSON files).
	CmdName        string    // Command name is appended to the ApiURL like http://apiurl/CmdName/. This represents one binary.
	BinURL         string    // Base URL for full binary downloads.
	DiffURL        string    // Base URL for diff downloads.
	BinGithubURL   string    // Base URL for full binary downloads.
	Dir            string    // Directory to store selfupdate state.
	ForceCheck     bool      // Check for update regardless of cktime timestamp
	CheckTime      int       // Time in hours before next check
	RandomizeTime  int       // Time in hours to randomize with CheckTime
	Requester      Requester // Optional parameter to override existing HTTP request handler
	Info           struct {
		Version string
		Sha256  []byte
		Desc    string
	}
	OnSuccessfulUpdate func() // Optional function to run after an update has successfully taken place
}

func (u *Updater) getExecRelativeDir(dir string) string {
	filename, _ := os.Executable()
	path := filepath.Join(filepath.Dir(filename), dir)
	return path
}

func canUpdate() (err error) {
	// get the directory the file exists in
	path, err := os.Executable()
	if err != nil {
		return
	}

	fileDir := filepath.Dir(path)
	fileName := filepath.Base(path)

	// attempt to open a file in the file's directory
	newPath := filepath.Join(fileDir, fmt.Sprintf(".%s.new", fileName))
	fp, err := os.OpenFile(newPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return
	}
	fp.Close()

	_ = os.Remove(newPath)
	return
}

// BackgroundRun starts the update check and apply cycle.
func (u *Updater) BackgroundRun() error {

	return u.BackgroundRunWithChannel("official")
}
func (u *Updater) BackgroundRunWithChannel(channel string) error {
	if channel == "" || channel == "official" {
		if err := os.MkdirAll(u.getExecRelativeDir(u.Dir), 0755); err != nil {
			// fail
			return err
		}
		// check to see if we want to check for updates based on version
		// and last update time
		if u.WantUpdate() {
			if err := canUpdate(); err != nil {
				// fail
				return err
			}

			u.SetUpdateTime()

			if err := u.Update(); err != nil {
				return err
			}
		}
	} else if channel == "github" {
		if err := os.MkdirAll(u.getExecRelativeDir(u.Dir), 0755); err != nil {
			// fail
			return err
		}
		if err := canUpdate(); err != nil {
			// fail
			return err
		}

		u.SetUpdateTime()

		if err := u.UpdateWithChannel(channel); err != nil {
			return err
		}
	}

	return nil
}

// WantUpdate returns boolean designating if an update is desired. If the app's version
// is `dev` WantUpdate will return false. If u.ForceCheck is true or cktime is after now
// WantUpdate will return true.
func (u *Updater) WantUpdate() bool {
	if u.CurrentVersion == "dev" || (!u.ForceCheck && u.NextUpdate().After(time.Now())) {
		return false
	}

	return true
}

// NextUpdate returns the next time update should be checked
func (u *Updater) NextUpdate() time.Time {
	path := u.getExecRelativeDir(u.Dir + upcktimePath)
	nextTime := readTime(path)

	return nextTime
}

// SetUpdateTime writes the next update time to the state file
func (u *Updater) SetUpdateTime() bool {
	path := u.getExecRelativeDir(u.Dir + upcktimePath)
	wait := time.Duration(u.CheckTime) * time.Hour
	// Add 1 to random time since max is not included
	waitrand := time.Duration(rand.Intn(u.RandomizeTime+1)) * time.Hour

	return writeTime(path, time.Now().Add(wait+waitrand))
}

// ClearUpdateState writes current time to state file
func (u *Updater) ClearUpdateState() {
	path := u.getExecRelativeDir(u.Dir + upcktimePath)
	os.Remove(path)
}
func (u *Updater) UpdateAvailableWithChannel(channel string) (bool, string, string, error) {

	path, err := os.Executable()
	if err != nil {
		return false, "", "", err
	}
	old, err := os.Open(path)
	if err != nil {
		return false, "", "", err
	}
	defer old.Close()

	//渠道选择
	if channel == "" || channel == "official" {
		err = u.fetchInfo()
		if err != nil {
			return false, "", "", err
		}
		// 比较版本号
		cmp := semver.Compare(u.Info.Version, u.CurrentVersion)
		// 如果更新的版本大于当前版本，返回 true，表示有可用的更新
		if cmp > 0 {
			return true, u.Info.Version, u.Info.Desc, nil
		} else {
			// 否则，返回 false，表示没有可用的更新
			return false, "", "", nil
		}
	} else if channel == "github" {
		err = u.fetchInfoGithub()
		if err != nil {
			return false, "", "", err
		}
		// 比较版本号
		cmp := semver.Compare(u.Info.Version, u.CurrentVersion)
		// 如果更新的版本大于当前版本，返回 true，表示有可用的更新
		if cmp > 0 {
			return true, u.Info.Version, u.Info.Desc, nil
		} else {
			// 否则，返回 false，表示没有可用的更新
			return false, "", "", nil
		}
	} else {
		// 否则，返回 false，表示没有可用的更新
		return false, "", "", nil
	}
}

// UpdateAvailable 默认从官方下载
func (u *Updater) UpdateAvailable() (bool, string, string, error) {
	return u.UpdateAvailableWithChannel("official")
}

// Update initiates the self update process
func (u *Updater) Update() error {
	path, err := os.Executable()
	if err != nil {
		return err
	}

	if resolvedPath, err := filepath.EvalSymlinks(path); err == nil {
		path = resolvedPath
	}

	// go fetch latest updates manifest
	err = u.fetchInfo()
	if err != nil {
		return err
	}

	// 检测是新版本才更新，否则不更新
	cmp := semver.Compare(u.Info.Version, u.CurrentVersion)
	if cmp <= 0 {
		return nil
	}

	old, err := os.Open(path)
	if err != nil {
		return err
	}
	defer old.Close()

	// if patch failed grab the full new bin
	bin, err := u.fetchAndVerifyFullBin()
	if err != nil {
		if err == ErrHashMismatch {
			log.Println("update: hash mismatch from full binary")
		} else {
			log.Println("update: fetching full binary,", err)
		}
		return err
	}

	// close the old binary before installing because on windows
	// it can't be renamed if a handle to the file is still open
	old.Close()

	err, errRecover := fromStream(bytes.NewBuffer(bin))
	if errRecover != nil {
		return fmt.Errorf("update and recovery errors: %q %q", err, errRecover)
	}
	if err != nil {
		return err
	}

	// update was successful, run func if set
	if u.OnSuccessfulUpdate != nil {
		u.OnSuccessfulUpdate()
	}

	return nil
}

// UpdateWithChannel 通过渠道来检测
func (u *Updater) UpdateWithChannel(channel string) error {
	path, err := os.Executable()
	if err != nil {
		return err
	}

	if resolvedPath, err := filepath.EvalSymlinks(path); err == nil {
		path = resolvedPath
	}

	if channel == "" || channel == "official" {
		// go fetch latest updates manifest
		err = u.fetchInfo()
		if err != nil {
			return err
		}

		// 检测是新版本才更新，否则不更新
		cmp := semver.Compare(u.Info.Version, u.CurrentVersion)
		if cmp <= 0 {
			return nil
		}

		old, err := os.Open(path)
		if err != nil {
			return err
		}
		defer old.Close()

		// if patch failed grab the full new bin
		bin, err := u.fetchAndVerifyFullBin()
		if err != nil {
			if err == ErrHashMismatch {
				log.Println("update: hash mismatch from full binary")
			} else {
				log.Println("update: fetching full binary,", err)
			}
			return err
		}

		// close the old binary before installing because on windows
		// it can't be renamed if a handle to the file is still open
		old.Close()

		err, errRecover := fromStream(bytes.NewBuffer(bin))
		if errRecover != nil {
			return fmt.Errorf("update and recovery errors: %q %q", err, errRecover)
		}
		if err != nil {
			return err
		}

		// update was successful, run func if set
		if u.OnSuccessfulUpdate != nil {
			u.OnSuccessfulUpdate()
		}
	} else if channel == "github" {
		err = u.fetchInfoGithub()
		if err != nil {
			return err
		}
		// 从 GitHub 下载资源
		r, err := u.fetch(u.BinGithubURL)
		if err != nil {
			return err
		}
		defer r.Close()

		// 创建临时目录用于解压文件
		tempDir, err := ioutil.TempDir("", "samwaf_beta_update"+u.Info.Version)
		if err != nil {
			return err
		}
		defer os.RemoveAll(tempDir)

		// 保存下载的文件到临时文件
		tempFile := filepath.Join(tempDir, "download")
		out, err := os.Create(tempFile)
		if err != nil {
			return err
		}

		_, err = io.Copy(out, r)
		out.Close()
		if err != nil {
			return err
		}

		// 根据文件类型和平台解压并获取正确的可执行文件
		var binPath string

		if strings.HasSuffix(u.BinGithubURL, ".exe") {
			//使用win7内核
			binPath = tempFile
		} else if strings.HasSuffix(u.BinGithubURL, ".zip") {
			// 情况 1: 从 ZIP 中提取 SamWaf64.exe
			err = utils.Unzip(tempFile, tempDir)
			if err != nil {
				return err
			}
			binPath = filepath.Join(tempDir, "SamWaf64.exe")
		} else if strings.HasSuffix(u.BinGithubURL, ".tar.gz") {
			// 处理 Linux 平台的 tar.gz 文件
			err = utils.ExtractTarGz(tempFile, tempDir)
			if err != nil {
				return err
			}

			if strings.Contains(u.BinGithubURL, "Linux_x86_64") {
				// 情况 2: 从 tar.gz 中提取 SamWafLinux64
				binPath = filepath.Join(tempDir, "SamWafLinux64")
			} else if strings.Contains(u.BinGithubURL, "Linux_arm64") {
				// 情况 3: 从 tar.gz 中提取 SamWafLinuxArm64
				binPath = filepath.Join(tempDir, "SamWafLinuxArm64")
			}
		}

		// 检查是否找到了可执行文件
		if binPath == "" {
			return errors.New("无法找到适合当前平台的可执行文件")
		}
		fileBytes, err := ioutil.ReadFile(binPath)
		if err != nil {
			return err
		}
		err, errRecover := fromStream(bytes.NewBuffer(fileBytes))
		if errRecover != nil {
			return fmt.Errorf("update and recovery errors: %q %q", err, errRecover)
		}
		if err != nil {
			return err
		}

		// update was successful, run func if set
		if u.OnSuccessfulUpdate != nil {
			u.OnSuccessfulUpdate()
		}
	}

	return nil
}

func fromStream(updateWith io.Reader) (err error, errRecover error) {
	updatePath, err := os.Executable()
	if err != nil {
		return
	}

	var newBytes []byte
	newBytes, err = ioutil.ReadAll(updateWith)
	if err != nil {
		return
	}

	// get the directory the executable exists in
	updateDir := filepath.Dir(updatePath)
	filename := filepath.Base(updatePath)

	// Copy the contents of of newbinary to a the new executable file
	newPath := filepath.Join(updateDir, fmt.Sprintf(".%s.new", filename))
	fp, err := os.OpenFile(newPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return
	}
	defer fp.Close()
	_, err = io.Copy(fp, bytes.NewReader(newBytes))

	// if we don't call fp.Close(), windows won't let us move the new executable
	// because the file will still be "in use"
	fp.Close()

	// this is where we'll move the executable to so that we can swap in the updated replacement
	oldPath := filepath.Join(updateDir, fmt.Sprintf(".%s.old", filename))

	// delete any existing old exec file - this is necessary on Windows for two reasons:
	// 1. after a successful update, Windows can't remove the .old file because the process is still running
	// 2. windows rename operations fail if the destination file already exists
	_ = os.Remove(oldPath)

	// move the existing executable to a new file in the same directory
	err = os.Rename(updatePath, oldPath)
	if err != nil {
		return
	}

	// move the new exectuable in to become the new program
	err = os.Rename(newPath, updatePath)

	if err != nil {
		// copy unsuccessful
		errRecover = os.Rename(oldPath, updatePath)
	} else {
		// copy successful, remove the old binary
		errRemove := os.Remove(oldPath)

		// windows has trouble with removing old binaries, so hide it instead
		if errRemove != nil {
			_ = hideFile(oldPath)
		}
	}

	return
}

// fetchInfo fetches the update JSON manifest at u.ApiURL/appname/platform.json?v=currentVersion
// and updates u.Info.
func (u *Updater) fetchInfo() error {
	r, err := u.fetch(u.ApiURL + url.QueryEscape(u.CmdName) + "/" + url.QueryEscape(plat) + ".json?v=" + global.GWAF_RELEASE_VERSION + "&u=" + global.GWAF_USER_CODE)
	if err != nil {
		return err
	}
	defer r.Close()
	err = json.NewDecoder(r).Decode(&u.Info)
	if err != nil {
		return err
	}
	if len(u.Info.Sha256) != sha256.Size {
		return errors.New("bad cmd hash in info")
	}
	return nil
}

// fetchInfoGithub 从GitHub获取最新beta版本信息
func (u *Updater) fetchInfoGithub() error {
	r, err := u.fetch(global.GUPDATE_GITHUB_VERSION_URL)
	if err != nil {
		return err
	}
	defer r.Close()

	// 解析GitHub API返回的JSON数据
	var githubRelease struct {
		TagName string `json:"tag_name"`
		Name    string `json:"name"`
		Body    string `json:"body"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
			Size               int64  `json:"size"`
			ContentType        string `json:"content_type"`
		} `json:"assets"`
	}

	err = json.NewDecoder(r).Decode(&githubRelease)
	if err != nil {
		return err
	}
	//判断tagname 是否包含beta
	if !strings.Contains(githubRelease.TagName, "beta") {
		//return errors.New("not beta version")
	}

	// 过滤掉debug版本，防止用户意外升级到debug版本
	if strings.Contains(githubRelease.TagName, "debug") || strings.Contains(strings.ToLower(githubRelease.Name), "debug") {
		return errors.New("debug version detected, skipping update to prevent accidental upgrade")
	}

	// 查找适合当前平台的资源
	var downloadURL string

	// 根据平台选择合适的下载文件
	platformSuffix := ""
	utils.IsSupportedWindows7Version()
	switch plat {
	case "windows-amd64":
		if utils.IsSupportedWindows7Version() {
			platformSuffix = "SamWaf64ForWin7Win8Win2008"
		} else {
			platformSuffix = "Windows_x86_64"
		}
	case "linux-amd64":
		platformSuffix = "Linux_x86_64"
	case "linux-arm64":
		platformSuffix = "Linux_arm64"
	case "darwin-amd64":
		platformSuffix = "Darwin_x86_64"
	case "darwin-arm64":
		platformSuffix = "Darwin_arm64"
	}

	// 查找匹配当前平台的资源，同时过滤掉debug版本
	for _, asset := range githubRelease.Assets {
		// 跳过包含DEBUG_SYMBOLS的文件
		if strings.Contains(asset.Name, "DEBUG_SYMBOLS") || strings.Contains(strings.ToUpper(asset.Name), "DEBUG") {
			continue
		}
		if strings.Contains(asset.Name, platformSuffix) {
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}

	// 如果没有找到适合的资源，返回错误
	if downloadURL == "" {
		return errors.New("no suitable release asset found for this platform")
	}
	u.BinGithubURL = downloadURL
	u.Info.Version = githubRelease.TagName
	u.Info.Desc = githubRelease.Body
	return nil
}

func (u *Updater) fetchAndVerifyPatch(old io.Reader) ([]byte, error) {
	bin, err := u.fetchAndApplyPatch(old)
	if err != nil {
		return nil, err
	}
	if !verifySha(bin, u.Info.Sha256) {
		return nil, ErrHashMismatch
	}
	return bin, nil
}

func (u *Updater) fetchAndApplyPatch(old io.Reader) ([]byte, error) {
	r, err := u.fetch(u.DiffURL + url.QueryEscape(u.CmdName) + "/" + url.QueryEscape(u.CurrentVersion) + "/" + url.QueryEscape(u.Info.Version) + "/" + url.QueryEscape(plat))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	var buf bytes.Buffer
	err = binarydist.Patch(old, &buf, r)
	return buf.Bytes(), err
}

func (u *Updater) fetchAndVerifyFullBin() ([]byte, error) {
	bin, err := u.fetchBin()
	if err != nil {
		return nil, err
	}
	verified := verifySha(bin, u.Info.Sha256)
	if !verified {
		return nil, ErrHashMismatch
	}
	return bin, nil
}

func (u *Updater) fetchBin() ([]byte, error) {
	r, err := u.fetch(u.BinURL + url.QueryEscape(u.CmdName) + "/" + url.QueryEscape(u.Info.Version) + "/" + url.QueryEscape(plat) + ".gz")
	if err != nil {
		return nil, err
	}
	defer r.Close()
	buf := new(bytes.Buffer)
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	if _, err = io.Copy(buf, gz); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
func (u *Updater) fetch(url string) (io.ReadCloser, error) {
	if u.Requester == nil {
		return defaultHTTPRequester.Fetch(url)
	}

	readCloser, err := u.Requester.Fetch(url)
	if err != nil {
		return nil, err
	}

	if readCloser == nil {
		return nil, fmt.Errorf("Fetch was expected to return non-nil ReadCloser")
	}

	return readCloser, nil
}

func (u *Updater) GetHttps(url string) {

}

func readTime(path string) time.Time {
	p, err := ioutil.ReadFile(path)
	if os.IsNotExist(err) {
		return time.Time{}
	}
	if err != nil {
		return time.Now().Add(1000 * time.Hour)
	}
	t, err := time.Parse(time.RFC3339, string(p))
	if err != nil {
		return time.Now().Add(1000 * time.Hour)
	}
	return t
}

func verifySha(bin []byte, sha []byte) bool {
	h := sha256.New()
	h.Write(bin)
	return bytes.Equal(h.Sum(nil), sha)
}

func writeTime(path string, t time.Time) bool {
	return ioutil.WriteFile(path, []byte(t.Format(time.RFC3339)), 0644) == nil
}

// BackupExecutable 备份当前可执行文件
func BackupExecutable() error {
	// 获取当前可执行文件路径
	execPath, err := os.Executable()
	if err != nil {
		return err
	}

	// 如果是符号链接，获取实际路径
	if resolvedPath, err := filepath.EvalSymlinks(execPath); err == nil {
		execPath = resolvedPath
	}

	// 获取当前目录
	currentDir := utils.GetCurrentDir()

	// 创建备份目录
	backupDir := filepath.Join(currentDir, "data", "backups_bin")

	// 获取文件名（不带路径）
	fileName := filepath.Base(execPath)
	fileNameWithoutExt := strings.TrimSuffix(fileName, filepath.Ext(fileName))

	// 备份文件
	_, err = utils.BackupFile(execPath, backupDir, fileNameWithoutExt, 5)
	return err
}
