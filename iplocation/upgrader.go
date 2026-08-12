package iplocation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// IP 库在线下载。
//
// 背景：GeoLite2 受 MaxMind 再分发授权限制已去内嵌，IPv6 改用 ip2region_v6.xdb；
// 但该文件约 35MB，塞进二进制会毁掉 SamWaf 的轻量定位，所以做成按需下载。
// ip2region 是 Apache-2.0，SamWaf 可以合法转发分发。
//
// 用户也可以完全不走这里，自己从 Gitee/GitHub 下载 xdb 放进 data/ 目录，程序照常加载：
//   https://gitee.com/lionsoul/ip2region/tree/master/data
//   https://github.com/lionsoul2014/ip2region/tree/master/data
//
// 本包不引用 global/utils —— global 反过来依赖 iplocation，会成环。
// 因此升级源 URL 和带 SSRF 防护的 http.Client 都由主程序通过 ConfigureUpgrader 注入。

// DatabaseFile 一个数据文件槽位的静态元数据。
//
// 这是厂商知识的**唯一出处**：文件名、能不能在线下载、上传要带什么参数、许可证怎么说，
// 全部在这里定义，manager / api / 前端都从这里取，避免同一份映射被抄好几遍。
type DatabaseFile struct {
	Key          string `json:"key"`          // 稳定标识，与状态接口 file_exists 的键一致
	FileName     string `json:"file_name"`    // 落到 data/ 下的文件名（用户手工放也必须用这个名字）
	Desc         string `json:"desc"`         // 界面展示名
	IPType       string `json:"ip_type"`      // ipv4 / ipv6 / both
	Source       string `json:"source"`       // ip2region / geolite2 / ipdb
	Downloadable bool   `json:"downloadable"` // SamWaf 能否合法转发分发（许可证决定，不是技术决定）
	UploadType   string `json:"upload_type"`  // 上传接口的 type 参数
	Accept       string `json:"accept"`       // 允许的文件后缀
	License      string `json:"license"`      // 展示用
	ObtainHint   string `json:"obtain_hint"`  // 不可在线下载时，告诉用户去哪拿
}

// KnownDatabases 所有已知的数据文件槽位。
//
// Downloadable 只看许可证：ip2region 系列是 Apache-2.0，SamWaf 可以转发分发；
// GeoLite2 受 MaxMind 商业再分发授权限制、ipdb 是 ipip.net 的免费库，都只能由用户自行获取后上传。
var KnownDatabases = []DatabaseFile{
	{
		Key: "ip2region_v6", FileName: "ip2region_v6.xdb", Desc: "ip2region IPv6 地区库",
		IPType: "ipv6", Source: "ip2region", Downloadable: true,
		UploadType: "ipv6", Accept: ".xdb", License: "Apache-2.0",
	},
	{
		Key: "ip2region_v4", FileName: "ip2region.xdb", Desc: "ip2region IPv4 地区库",
		IPType: "ipv4", Source: "ip2region", Downloadable: true,
		UploadType: "ipv4", Accept: ".xdb", License: "Apache-2.0",
	},
	{
		Key: "geolite2", FileName: "GeoLite2-Country.mmdb", Desc: "GeoLite2 国家库（IPv4+IPv6）",
		IPType: "both", Source: "geolite2", Downloadable: false,
		UploadType: "ipv6", Accept: ".mmdb", License: "MaxMind EULA",
		ObtainHint: "受 MaxMind 再分发授权限制，需自行到 MaxMind 官网下载后上传",
	},
	{
		Key: "ipdb", FileName: "iplocation.ipdb", Desc: "IPDB 库（IPv4+IPv6）",
		IPType: "both", Source: "ipdb", Downloadable: false,
		UploadType: "ipdb", Accept: ".ipdb", License: "ipip.net 免费库",
		ObtainHint: "需自行从 ipip.net 获取后上传",
	},
}

// DatabaseByKey 按 key 取槽位定义。
// 同时充当白名单：外部传进来的 key 只能命中这张表，杜绝写到 data/ 之外的位置。
func DatabaseByKey(key string) (DatabaseFile, bool) {
	for _, f := range KnownDatabases {
		if f.Key == key {
			return f, true
		}
	}
	return DatabaseFile{}, false
}

// fileNameByKey 返回 key 对应的落盘文件名；不可在线下载的槽位返回空串，
// 这样下载入口永远碰不到 GeoLite2 / ipdb。
func fileNameByKey(key string) string {
	f, ok := DatabaseByKey(key)
	if !ok || !f.Downloadable {
		return ""
	}
	return f.FileName
}

// UpgradeConfig 下载所需的外部上下文，由主程序注入。
type UpgradeConfig struct {
	// UpdateVersionURL 升级源根 URL，例如 https://update.samwaf.com/
	UpdateVersionURL string
	// NewClient 返回一枚带 SSRF 防护的 http.Client；为 nil 时退化为普通客户端。
	// 该 client 负责跳转链上每一跳的校验，初始 URL 由 ValidateURL 把关。
	NewClient func() *http.Client
	// ValidateURL 校验初始 URL 是否可以对外请求（仅 http/https、目标为公网）。
	// 清单里的下载地址来自远端，必须先过这一关再发请求，否则升级源被篡改就成了 SSRF 跳板。
	ValidateURL func(rawURL string) (bool, string)
	// NotifyFunc 下载结果回调，用于推送 WS 消息。success=false 表示失败。
	NotifyFunc func(success bool, msg string)
}

var upgradeCfg atomic.Pointer[UpgradeConfig]

// ConfigureUpgrader 注入下载所需上下文。main 启动阶段调用一次即可。
func ConfigureUpgrader(c UpgradeConfig) {
	cp := c
	upgradeCfg.Store(&cp)
}

func currentUpgradeCfg() UpgradeConfig {
	if c := upgradeCfg.Load(); c != nil {
		return *c
	}
	return UpgradeConfig{}
}

// httpTimeout 下载超时。IPv6 库约 35MB，慢网也得给足，否则永远下不完。
const httpTimeout = 10 * time.Minute

func newHTTPClient() *http.Client {
	cfg := currentUpgradeCfg()
	var c *http.Client
	if cfg.NewClient != nil {
		c = cfg.NewClient()
	}
	if c == nil {
		c = &http.Client{}
	}
	c.Timeout = httpTimeout
	return c
}

// remoteFile 远端清单里单个文件的元数据。
type remoteFile struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// remoteManifest 远端 latest.json。
//
// 约定：{UpdateVersionURL}ipdb-dataset/latest.json
//
//	{
//	  "version": "2026.08.11",
//	  "changelog": "...",
//	  "files": {
//	     "ip2region_v6": {"url": "...", "sha256": "...", "size": 36700160}
//	  }
//	}
type remoteManifest struct {
	Version   string                `json:"version"`
	Changelog string                `json:"changelog"`
	Files     map[string]remoteFile `json:"files"`
}

// FileUpgradeInfo 单个槽位的完整状态：静态元数据 + 本地情况 + 远端情况。
//
// 界面上「在线下载」和「上传」是同一张表的两个操作列，所以这里必须把
// 不可在线下载的槽位（GeoLite2 / ipdb）也一并返回，否则用户看不到它们的本地状态。
type FileUpgradeInfo struct {
	DatabaseFile         // 内嵌静态元数据（key/file_name/desc/downloadable/upload_type/accept/license/...）
	Builtin       bool   `json:"builtin"`        // 该槽位有随程序内置的数据兜底
	Available     bool   `json:"available"`      // 远端有这个文件可下
	LocalExists   bool   `json:"local_exists"`   // 本地 data/ 下已经有了
	LocalSize     int64  `json:"local_size"`     // 本地文件大小
	LocalModTime  string `json:"local_mod_time"` // 本地文件修改时间
	LocalVersion  string `json:"local_version"`  // 本地记录的版本（本模块下载时写入；用户手工放的为空）
	RemoteSize    int64  `json:"remote_size"`    // 远端文件大小
	LatestVersion string `json:"latest_version"` // 远端版本
	NeedUpdate    bool   `json:"need_update"`    // 本地缺失或版本落后
}

// UpgradeInfo 一次检查的整体结果。
type UpgradeInfo struct {
	LatestVersion string            `json:"latest_version"`
	Changelog     string            `json:"changelog"`
	LastCheckAt   string            `json:"last_check_at"`
	Files         []FileUpgradeInfo `json:"files"`
	// DataDir 服务器上放数据文件的绝对路径。
	// 官方源在部分网络下很慢，用户自己下好文件要知道往哪放，所以直接把路径显示出来。
	DataDir string `json:"data_dir"`
}

// downloading 并发保护：一次只允许一个下载流程，避免同一文件被两个请求同时写。
var downloading atomic.Bool

// 下载状态机。前端按这几个状态决定进度条怎么画。
const (
	StateIdle        = "idle"        // 没有正在进行的下载
	StateDownloading = "downloading" // 正在下载，有字节进度
	StateVerifying   = "verifying"   // 下载完了在算 sha256（35MB 也要一会儿）
	StateApplying    = "applying"    // 落盘 + 热加载
	StateDone        = "done"        // 成功
	StateFailed      = "failed"      // 失败，Message 里是原因
	StateCanceled    = "canceled"    // 用户主动取消
)

// cancelCurrent 取消当前下载。官方源在部分网络下很慢，用户等不下去时要能停，
// 转而自己从 Gitee/GitHub 下好丢进 data 目录。
var (
	cancelMu      sync.Mutex
	cancelCurrent context.CancelFunc
)

func setCancelFunc(fn context.CancelFunc) {
	cancelMu.Lock()
	cancelCurrent = fn
	cancelMu.Unlock()
}

// CancelUpgrade 取消正在进行的下载。没有任务在跑时返回错误。
func CancelUpgrade() error {
	cancelMu.Lock()
	fn := cancelCurrent
	cancelMu.Unlock()
	if fn == nil || !downloading.Load() {
		return fmt.Errorf("当前没有正在进行的下载")
	}
	fn()
	return nil
}

// DownloadProgress 一次下载的实时进度，供前端轮询展示。
//
// 下载是同步长任务（IPv6 库 35MB，慢网要几分钟），如果让 HTTP 请求一直挂着，
// 用户只能看到一个转圈，不知道下到哪了、还要多久。所以改成：
// apply 接口起个 goroutine 立刻返回，前端轮询本结构画进度条。
type DownloadProgress struct {
	Key        string  `json:"key"`
	FileName   string  `json:"file_name"`
	Total      int64   `json:"total"`      // 总字节数，取自清单的 size（Content-Length 可能缺失）
	Downloaded int64   `json:"downloaded"` // 已下载字节数
	Percent    float64 `json:"percent"`    // 0~100，Total 未知时恒为 0
	State      string  `json:"state"`
	Message    string  `json:"message"`
	UpdatedAt  string  `json:"updated_at"`
}

var (
	progressMu sync.RWMutex
	progress   = DownloadProgress{State: StateIdle}
)

// GetProgress 返回当前下载进度的快照。
func GetProgress() DownloadProgress {
	progressMu.RLock()
	defer progressMu.RUnlock()
	return progress
}

func setProgress(mutate func(p *DownloadProgress)) {
	progressMu.Lock()
	defer progressMu.Unlock()
	mutate(&progress)
	if progress.Total > 0 {
		progress.Percent = float64(progress.Downloaded) * 100 / float64(progress.Total)
		if progress.Percent > 100 {
			progress.Percent = 100
		}
	} else {
		progress.Percent = 0
	}
	progress.UpdatedAt = time.Now().Format("2006-01-02 15:04:05")
}

// progressWriter 边写边记字节数。
// 按 256KB 一档节流：35MB 下载会产生上万次 Write，每次都抢一把写锁纯属浪费。
type progressWriter struct {
	n      int64
	lastAt int64
}

const progressFlushStep = 256 << 10

func (w *progressWriter) Write(p []byte) (int, error) {
	w.n += int64(len(p))
	if w.n-w.lastAt >= progressFlushStep {
		w.lastAt = w.n
		n := w.n
		setProgress(func(pr *DownloadProgress) { pr.Downloaded = n })
	}
	return len(p), nil
}

// localVersionFile 记录本模块下载过的文件版本，供下次比对。
// 用户手工放进 data/ 的文件不会出现在这里，此时 LocalVersion 为空、NeedUpdate 为 true，
// 界面上表现为"可更新"，点了也只是覆盖成官方版本，不会有副作用。
const localVersionFile = "ipdb_version.json"

type localVersions map[string]string

func readLocalVersions(dataDir string) localVersions {
	v := localVersions{}
	b, err := os.ReadFile(filepath.Join(dataDir, localVersionFile))
	if err != nil {
		return v
	}
	_ = json.Unmarshal(b, &v)
	return v
}

func writeLocalVersion(dataDir, key, version string) {
	v := readLocalVersions(dataDir)
	v[key] = version
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(dataDir, localVersionFile), b, 0o600)
}

// CheckUpgrade 查询远端清单，返回每个可下载文件的本地/远端对比结果。
func CheckUpgrade(dataDir string) (*UpgradeInfo, error) {
	info := &UpgradeInfo{LastCheckAt: time.Now().Format(time.RFC3339), DataDir: dataDir}
	if abs, err := filepath.Abs(dataDir); err == nil {
		info.DataDir = abs
	}

	// 先把本地状态填上：即使远端不可达（内网环境），界面也能看到本地有什么。
	// 四个槽位全都返回，包括不可在线下载的 GeoLite2 / ipdb —— 界面上它们和可下载的
	// 在同一张表里，只是操作列只有「上传」没有「下载」。
	local := readLocalVersions(dataDir)
	for _, f := range KnownDatabases {
		fi := FileUpgradeInfo{DatabaseFile: f, LocalVersion: local[f.Key]}
		fi.Builtin = HasBuiltinFile(f.Key)
		if st, err := os.Stat(filepath.Join(dataDir, f.FileName)); err == nil {
			fi.LocalExists = true
			fi.LocalSize = st.Size()
			fi.LocalModTime = st.ModTime().Format("2006-01-02 15:04:05")
		}
		info.Files = append(info.Files, fi)
	}

	cfg := currentUpgradeCfg()
	if cfg.UpdateVersionURL == "" {
		return info, fmt.Errorf("未配置升级源")
	}
	manifest, err := fetchManifest(context.Background(), strings.TrimRight(cfg.UpdateVersionURL, "/")+"/ipdb-dataset/latest.json")
	if err != nil {
		return info, err
	}
	info.LatestVersion = manifest.Version
	info.Changelog = manifest.Changelog
	for i := range info.Files {
		rf, ok := manifest.Files[info.Files[i].Key]
		if !ok || rf.URL == "" {
			continue
		}
		info.Files[i].Available = true
		info.Files[i].RemoteSize = rf.Size
		info.Files[i].LatestVersion = manifest.Version
		info.Files[i].NeedUpdate = !info.Files[i].LocalExists || info.Files[i].LocalVersion != manifest.Version
	}
	return info, nil
}

// StartUpgrade 异步启动一次下载，立刻返回，进度由 GetProgress 查询。
//
// 之所以不让接口同步等：35MB 在慢网上要几分钟，HTTP 请求挂那么久既容易被网关掐断，
// 用户也只能看到一个转圈，不知道下到哪、还剩多少。
// 参数校验（key 是否支持、是否已有任务在跑）在返回前同步做完，这样前端能立刻收到错误。
func StartUpgrade(dataDir, key string, reload func() error) error {
	fileName := fileNameByKey(key)
	if fileName == "" {
		return fmt.Errorf("不支持下载的数据文件: %s", key)
	}
	if !downloading.CompareAndSwap(false, true) {
		return fmt.Errorf("正在下载中，请稍后")
	}
	setProgress(func(p *DownloadProgress) {
		*p = DownloadProgress{Key: key, FileName: fileName, State: StateDownloading}
	})
	ctx, cancel := context.WithCancel(context.Background())
	setCancelFunc(cancel)
	go func() {
		defer func() {
			cancel()
			setCancelFunc(nil)
			downloading.Store(false)
		}()
		if err := doUpgrade(ctx, dataDir, key, fileName, reload); err != nil {
			// 用户点了取消：不算失败，也别弹错误提示
			if ctx.Err() != nil {
				setProgress(func(p *DownloadProgress) {
					p.State = StateCanceled
					p.Message = "已取消下载"
				})
				return
			}
			msg := err.Error()
			setProgress(func(p *DownloadProgress) {
				p.State = StateFailed
				p.Message = msg
			})
			return
		}
		setProgress(func(p *DownloadProgress) {
			p.State = StateDone
			p.Downloaded = p.Total
			p.Message = fmt.Sprintf("%s 下载完成并已生效", fileName)
		})
	}()
	return nil
}

// ApplyUpgrade 同步下载指定 key 的数据文件并落到 dataDir。
// 供单测与命令行场景使用；管理端界面走 StartUpgrade + GetProgress。
func ApplyUpgrade(dataDir, key string, reload func() error) error {
	fileName := fileNameByKey(key)
	if fileName == "" {
		return fmt.Errorf("不支持下载的数据文件: %s", key)
	}
	if !downloading.CompareAndSwap(false, true) {
		return fmt.Errorf("正在下载中，请稍后")
	}
	defer downloading.Store(false)
	setProgress(func(p *DownloadProgress) {
		*p = DownloadProgress{Key: key, FileName: fileName, State: StateDownloading}
	})
	err := doUpgrade(context.Background(), dataDir, key, fileName, reload)
	if err != nil {
		msg := err.Error()
		setProgress(func(p *DownloadProgress) {
			p.State = StateFailed
			p.Message = msg
		})
		return err
	}
	setProgress(func(p *DownloadProgress) {
		p.State = StateDone
		p.Downloaded = p.Total
	})
	return nil
}

// doUpgrade 真正的下载流程。
//
// 取清单 → 下载到 .downloading 临时文件 → sha256 校验 → 原子改名覆盖 → 记录版本 → 回调重载。
// 校验不通过就把临时文件删掉，绝不覆盖现有可用的库——宁可保持旧数据，也不能让地区判定基于一个坏文件。
// reload 由调用方传入（通常是 Manager.ReloadFromConfig 的包装），下载完立即生效，无需重启。
func doUpgrade(ctx context.Context, dataDir, key, fileName string, reload func() error) error {
	cfg := currentUpgradeCfg()
	if cfg.UpdateVersionURL == "" {
		return notifyErr(fmt.Errorf("未配置升级源"))
	}
	manifest, err := fetchManifest(ctx, strings.TrimRight(cfg.UpdateVersionURL, "/")+"/ipdb-dataset/latest.json")
	if err != nil {
		return notifyErr(fmt.Errorf("获取升级清单失败: %w", err))
	}
	rf, ok := manifest.Files[key]
	if !ok || rf.URL == "" {
		return notifyErr(fmt.Errorf("升级源暂未提供 %s", fileName))
	}
	// 总大小取自清单：响应可能是分块传输、没有 Content-Length，那时就画不出百分比了
	setProgress(func(p *DownloadProgress) { p.Total = rf.Size })

	if err = os.MkdirAll(dataDir, 0o755); err != nil {
		return notifyErr(fmt.Errorf("创建数据目录失败: %w", err))
	}
	dst := filepath.Join(dataDir, fileName)
	tmp := dst + ".downloading"
	defer os.Remove(tmp) // 成功时已改名，这里是失败路径的清理

	if err = downloadFile(ctx, rf.URL, tmp); err != nil {
		// 取消不算失败，交给上层置成 canceled 状态，别推一条"下载失败"的告警
		if ctx.Err() != nil {
			return err
		}
		return notifyErr(fmt.Errorf("下载 %s 失败: %w", fileName, err))
	}

	if rf.SHA256 != "" {
		setProgress(func(p *DownloadProgress) { p.State = StateVerifying })
		actual, err2 := fileSHA256(tmp)
		if err2 != nil {
			return notifyErr(fmt.Errorf("校验 %s 失败: %w", fileName, err2))
		}
		if !strings.EqualFold(actual, rf.SHA256) {
			return notifyErr(fmt.Errorf("%s 校验不通过，预期 %s 实际 %s", fileName, rf.SHA256, actual))
		}
	}

	setProgress(func(p *DownloadProgress) { p.State = StateApplying })
	// Windows 上 os.Rename 不能覆盖已存在的文件，先删旧的。
	// 此时新文件已校验通过，删旧文件是安全的。
	_ = os.Remove(dst)
	if err = os.Rename(tmp, dst); err != nil {
		return notifyErr(fmt.Errorf("替换 %s 失败: %w", fileName, err))
	}
	writeLocalVersion(dataDir, key, manifest.Version)

	if reload != nil {
		if err = reload(); err != nil {
			return notifyErr(fmt.Errorf("%s 已下载但重载失败: %w", fileName, err))
		}
	}
	notify(true, fmt.Sprintf("%s 下载并生效成功，版本 %s", fileName, manifest.Version))
	return nil
}

func notify(success bool, msg string) {
	if f := currentUpgradeCfg().NotifyFunc; f != nil {
		f(success, msg)
	}
}

func notifyErr(err error) error {
	notify(false, err.Error())
	return err
}

// checkURL 用注入的校验函数把关一个对外地址。未注入时不拦（单测里用 httptest 本地地址）。
func checkURL(rawURL string) error {
	f := currentUpgradeCfg().ValidateURL
	if f == nil {
		return nil
	}
	if ok, reason := f(rawURL); !ok {
		return fmt.Errorf("地址不被允许(%s): %s", reason, rawURL)
	}
	return nil
}

func fetchManifest(ctx context.Context, url string) (*remoteManifest, error) {
	if err := checkURL(url); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := newHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest HTTP %d", resp.StatusCode)
	}
	var m remoteManifest
	if err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

func downloadFile(ctx context.Context, url, dst string) error {
	if err := checkURL(url); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := newHTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()

	// 响应带了 Content-Length 就用它修正总大小（比清单里的更准）
	if resp.ContentLength > 0 {
		total := resp.ContentLength
		setProgress(func(p *DownloadProgress) { p.Total = total })
	}

	// 限个上限，防止升级源被替换后拿一个超大响应把磁盘写满
	pw := &progressWriter{}
	_, err = io.Copy(io.MultiWriter(f, pw), io.LimitReader(resp.Body, 512<<20))
	if err != nil {
		return err
	}
	// 收尾补一次：节流会让最后不足 256KB 的部分没被记上，不补的话进度条永远差一口气
	n := pw.n
	setProgress(func(p *DownloadProgress) { p.Downloaded = n })
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
