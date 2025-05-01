package wafupdate

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
	"testing"
	"time"
)

func TestUpdaterFetchMustReturnNonNilReaderCloser(t *testing.T) {
	mr := &mockRequester{}
	mr.handleRequest(
		func(url string) (io.ReadCloser, error) {
			return nil, nil
		})
	updater := createUpdater(mr)
	updater.CheckTime = 24
	updater.RandomizeTime = 24

	err := updater.BackgroundRun()

	if err != nil {
		equals(t, "Fetch was expected to return non-nil ReadCloser", err.Error())
	} else {
		t.Log("Expected an error")
		t.Fail()
	}
}

func TestUpdaterWithEmptyPayloadNoErrorNoUpdate(t *testing.T) {
	mr := &mockRequester{}
	mr.handleRequest(
		func(url string) (io.ReadCloser, error) {
			equals(t, "http://updates.yourdomain.com/myapp/linux-amd64.json", url)
			return newTestReaderCloser("{}"), nil
		})
	updater := createUpdater(mr)
	updater.CheckTime = 24
	updater.RandomizeTime = 24

	err := updater.BackgroundRun()
	if err != nil {
		t.Errorf("Error occurred: %#v", err)
	}
}

func TestUpdaterCheckTime(t *testing.T) {
	mr := &mockRequester{}
	mr.handleRequest(
		func(url string) (io.ReadCloser, error) {
			equals(t, "http://updates.yourdomain.com/myapp/linux-amd64.json", url)
			return newTestReaderCloser("{}"), nil
		})

	// Run test with various time
	runTestTimeChecks(t, mr, 0, 0, false)
	runTestTimeChecks(t, mr, 0, 5, true)
	runTestTimeChecks(t, mr, 1, 0, true)
	runTestTimeChecks(t, mr, 100, 100, true)
}

// Helper function to run check time tests
func runTestTimeChecks(t *testing.T, mr *mockRequester, checkTime int, randomizeTime int, expectUpdate bool) {
	updater := createUpdater(mr)
	updater.ClearUpdateState()
	updater.CheckTime = checkTime
	updater.RandomizeTime = randomizeTime

	updater.BackgroundRun()

	if updater.WantUpdate() == expectUpdate {
		t.Errorf("WantUpdate returned %v; want %v", updater.WantUpdate(), expectUpdate)
	}

	maxHrs := time.Duration(updater.CheckTime+updater.RandomizeTime) * time.Hour
	maxTime := time.Now().Add(maxHrs)

	if !updater.NextUpdate().Before(maxTime) {
		t.Errorf("NextUpdate should less than %s hrs (CheckTime + RandomizeTime) from now; now %s; next update %s", maxHrs, time.Now(), updater.NextUpdate())
	}

	if maxHrs > 0 && !updater.NextUpdate().After(time.Now()) {
		t.Errorf("NextUpdate should be after now")
	}
}

func TestUpdaterWithEmptyPayloadNoErrorNoUpdateEscapedPath(t *testing.T) {
	mr := &mockRequester{}
	mr.handleRequest(
		func(url string) (io.ReadCloser, error) {
			equals(t, "http://updates.yourdomain.com/myapp%2Bfoo/darwin-amd64.json", url)
			return newTestReaderCloser("{}"), nil
		})
	updater := createUpdaterWithEscapedCharacters(mr)

	err := updater.BackgroundRun()
	if err != nil {
		t.Errorf("Error occurred: %#v", err)
	}
}

func TestUpdateAvailable(t *testing.T) {
	mr := &mockRequester{}
	mr.handleRequest(
		func(url string) (io.ReadCloser, error) {
			equals(t, "https://update.samwaf.com/samwaf_update/windows-amd64.json", url)
			return newTestReaderCloser(`{
    "Version": "v1.0.30",
    "Sha256": "Q2vvTOW0p69A37StVANN+/ko1ZQDTElomq7fVcex/02=",
	"Desc":"fixsamebug"
}`), nil
		})
	updater := createUpdater(mr)

	available, ver, desc, err := updater.UpdateAvailable()
	if err != nil {
		t.Errorf("Error occurred: %#v", err)
	}
	equals(t, true, available)
	equals(t, "v1.0.30", ver)
	equals(t, "fixsamebug", desc)
}

func createUpdater(mr *mockRequester) *Updater {
	return &Updater{
		CurrentVersion: "1.2",
		ApiURL:         "http://updates.yourdomain.com/",
		BinURL:         "http://updates.yourdownmain.com/",
		DiffURL:        "http://updates.yourdomain.com/",
		Dir:            "update/",
		CmdName:        "myapp", // app name
		Requester:      mr,
	}
}

func createUpdaterWithEscapedCharacters(mr *mockRequester) *Updater {
	return &Updater{
		CurrentVersion: "1.2+foobar",
		ApiURL:         "http://updates.yourdomain.com/",
		BinURL:         "http://updates.yourdownmain.com/",
		DiffURL:        "http://updates.yourdomain.com/",
		Dir:            "update/",
		CmdName:        "myapp+foo", // app name
		Requester:      mr,
	}
}

func equals(t *testing.T, expected, actual interface{}) {
	if expected != actual {
		t.Logf("Expected: %#v got %#v\n", expected, actual)
		t.Fail()
	}
}

type testReadCloser struct {
	buffer *bytes.Buffer
}

func newTestReaderCloser(payload string) io.ReadCloser {
	return &testReadCloser{buffer: bytes.NewBufferString(payload)}
}

func (trc *testReadCloser) Read(p []byte) (n int, err error) {
	return trc.buffer.Read(p)
}

func (trc *testReadCloser) Close() error {
	return nil
}
func TestUpdater_GetHttps(t *testing.T) {
	resp, err := http.Get("https://update.samwaf.com/samwaf_update/windows-amd64.json")
	if err != nil {
		println(err)
	} else {
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)

		var strbody = "[" + string(body) + "]"
		println(strbody)
	}
}

// 测试 fetchInfoGithub 在实际环境中的行为
func TestFetchInfoGithubIntegration(t *testing.T) {

	// 创建更新器
	updater := &Updater{
		CurrentVersion: "v1.0.0",
	}

	// 调用被测试的函数
	err := updater.fetchInfoGithub()
	if err != nil {
		t.Fatalf("获取 GitHub 信息失败: %v", err)
	}

	// 验证结果
	if updater.BinGithubURL == "" {
		t.Error("下载 URL 为空")
	}

	if updater.Info.Version == "" {
		t.Error("版本为空")
	}

	if updater.Info.Desc == "" {
		t.Error("描述为空")
	}

	t.Logf("获取到的版本: %s", updater.Info.Version)
	t.Logf("下载 URL: %s", updater.BinGithubURL)
	t.Logf("版本说明 Desc: %s", updater.Info.Desc)
}
