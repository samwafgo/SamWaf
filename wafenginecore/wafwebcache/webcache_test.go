package wafwebcache

import (
	"SamWaf/cache"
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// 初始化测试环境
func setupTestEnv() {
	// 初始化缓存
	if global.GCACHE_WAFCACHE == nil {
		global.GCACHE_WAFCACHE = cache.InitWafCache()
	}
	//初始化日志
	zlog.InitZLog(global.GWAF_RELEASE, "json")
}

// 清理测试环境
func cleanupTestEnv(tempDir string) {
	// 清理临时目录
	if tempDir != "" {
		os.RemoveAll(tempDir)
	}
}

// 创建测试请求
func createTestRequest(method, uri string) *http.Request {
	req, _ := http.NewRequest(method, uri, nil)
	return req
}

// 创建测试主机安全配置
func createTestHostSafe(hostCode string, cacheRules []model.CacheRule) *wafenginmodel.HostSafe {
	return &wafenginmodel.HostSafe{
		Host: model.Hosts{
			Code: hostCode,
		},
		CacheRule: cacheRules,
	}
}

// 创建测试缓存配置
func createTestCacheConfig(isEnable int, location, dir string) model.CacheConfig {
	return model.CacheConfig{
		IsEnableCache: isEnable,
		CacheLocation: location,
		CacheDir:      dir,
	}
}

// 测试内存缓存存储和加载
func TestMemoryCache(t *testing.T) {
	setupTestEnv()

	hostCode := "test_host"
	key := "test_key"
	testData := []byte("test data content")
	timeout := 10

	// 测试存储到内存缓存
	storeMemory(hostCode, key, testData, timeout)

	// 测试从内存缓存加载
	data := loadFormMemory(hostCode, key)
	if data == nil {
		t.Fatalf("从内存缓存加载失败")
	}

	if string(data) != string(testData) {
		t.Fatalf("加载的数据与存储的数据不匹配，期望: %s, 实际: %s", string(testData), string(data))
	}
}

// 测试文件缓存存储和加载
func TestFileCache(t *testing.T) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "webcache_test")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer cleanupTestEnv(tempDir)

	hostCode := "test_host"
	key := "test_key"
	testData := []byte("test file cache content")
	timeout := 60

	// 测试存储到文件缓存
	storeFile(hostCode, key, testData, tempDir, timeout)

	// 测试从文件缓存加载
	data := loadFormFile(hostCode, key, tempDir)
	if data == nil {
		t.Fatalf("从文件缓存加载失败")
	}

	if string(data) != string(testData) {
		t.Fatalf("加载的数据与存储的数据不匹配，期望: %s, 实际: %s", string(testData), string(data))
	}
}

// 测试基本缓存规则匹配
func TestBasicCacheRuleMatching(t *testing.T) {
	// 创建测试规则
	rules := []model.CacheRule{
		{
			RuleName:      "后缀匹配规则",
			RuleType:      1,
			RuleContent:   ".jpg;.png;.gif",
			ParamType:     1, // 忽略参数
			CacheTime:     3600,
			Priority:      10,
			RequestMethod: "GET",
		},
		{
			RuleName:      "目录匹配规则",
			RuleType:      2,
			RuleContent:   "/static/;/assets/",
			ParamType:     1, // 忽略参数
			CacheTime:     7200,
			Priority:      20,
			RequestMethod: "GET",
		},
		{
			RuleName:      "文件匹配规则",
			RuleType:      3,
			RuleContent:   "/index.html;/home.html",
			ParamType:     1, // 忽略参数
			CacheTime:     1800,
			Priority:      30,
			RequestMethod: "GET;HEAD",
		},
	}

	hostSafe := createTestHostSafe("test_host", rules)
	cacheConfig := createTestCacheConfig(1, "memory", "/tmp/cache")

	// 测试后缀匹配
	req1 := createTestRequest("GET", "http://example.com/image.jpg")
	req1.URL.RawQuery = "param=value"
	timeout1, err1 := checkCacheRule(hostSafe, cacheConfig, req1)
	if err1 != nil {
		t.Fatalf("后缀匹配规则测试失败: %v", err1)
	}
	if timeout1 != 3600 {
		t.Fatalf("后缀匹配规则返回的超时时间不正确，期望: 3600, 实际: %d", timeout1)
	}

	// 测试目录匹配（优先级更高）
	req2 := createTestRequest("GET", "http://example.com/static/image.jpg")
	req2.URL.RawQuery = "param=value"
	timeout2, err2 := checkCacheRule(hostSafe, cacheConfig, req2)
	if err2 != nil {
		t.Fatalf("目录匹配规则测试失败: %v", err2)
	}
	if timeout2 != 7200 {
		t.Fatalf("目录匹配规则返回的超时时间不正确，期望: 7200, 实际: %d", timeout2)
	}

	// 测试文件匹配（最高优先级）
	req3 := createTestRequest("HEAD", "http://example.com/index.html")
	req3.URL.RawQuery = "param=value"
	timeout3, err3 := checkCacheRule(hostSafe, cacheConfig, req3)
	if err3 != nil {
		t.Fatalf("文件匹配规则测试失败: %v", err3)
	}
	if timeout3 != 1800 {
		t.Fatalf("文件匹配规则返回的超时时间不正确，期望: 1800, 实际: %d", timeout3)
	}

	// 测试不匹配的请求
	req4 := createTestRequest("POST", "http://example.com/api/data")
	_, err4 := checkCacheRule(hostSafe, cacheConfig, req4)
	if err4 == nil {
		t.Fatalf("不匹配的请求应该返回错误")
	}
}

// 测试优先级规则匹配
func TestPriorityCacheRuleMatching(t *testing.T) {
	// 创建测试规则，优先级不同
	rules := []model.CacheRule{
		{
			RuleName:      "低优先级规则",
			RuleType:      1,
			RuleContent:   ".jpg",
			ParamType:     1,
			CacheTime:     1000,
			Priority:      10,
			RequestMethod: "GET",
		},
		{
			RuleName:      "中优先级规则",
			RuleType:      1,
			RuleContent:   ".jpg",
			ParamType:     1,
			CacheTime:     2000,
			Priority:      20,
			RequestMethod: "GET",
		},
		{
			RuleName:      "高优先级规则",
			RuleType:      1,
			RuleContent:   ".jpg",
			ParamType:     1,
			CacheTime:     3000,
			Priority:      30,
			RequestMethod: "GET",
		},
	}

	hostSafe := createTestHostSafe("test_host", rules)
	cacheConfig := createTestCacheConfig(1, "memory", "/tmp/cache")

	// 测试优先级匹配，应该返回优先级最高的规则
	req := createTestRequest("GET", "http://example.com/image.jpg")
	timeout, err := checkCacheRule(hostSafe, cacheConfig, req)
	if err != nil {
		t.Fatalf("优先级规则测试失败: %v", err)
	}
	if timeout != 3000 {
		t.Fatalf("优先级规则返回的超时时间不正确，期望: 3000, 实际: %d", timeout)
	}
}

// 测试参数处理类型
func TestParamTypeCacheRuleMatching(t *testing.T) {
	// 创建测试规则，参数处理类型不同
	rules := []model.CacheRule{
		{
			RuleName:      "忽略参数规则",
			RuleType:      3,
			RuleContent:   "/data.html",
			ParamType:     1, // 忽略参数
			CacheTime:     1000,
			Priority:      10,
			RequestMethod: "GET",
		},
		{
			RuleName:      "完整参数规则",
			RuleType:      3,
			RuleContent:   "/data.html",
			ParamType:     2, // 完整参数
			CacheTime:     2000,
			Priority:      20,
			RequestMethod: "GET",
		},
	}

	hostSafe := createTestHostSafe("test_host", rules)
	cacheConfig := createTestCacheConfig(1, "memory", "/tmp/cache")

	// 测试不带参数的请求，应该匹配忽略参数规则
	req2 := createTestRequest("GET", "http://example.com/data.html")
	timeout2, err2 := checkCacheRule(hostSafe, cacheConfig, req2)
	if err2 != nil {
		t.Fatalf("参数处理类型测试失败: %v", err2)
	}
	if timeout2 != 2000 {
		t.Fatalf("参数处理类型测试返回的超时时间不正确，期望: 2000, 实际: %d", timeout2)
	}
}

// 测试具体参数值匹配
func TestSpecificParamValueMatching(t *testing.T) {
	// 创建测试规则，包含具体参数值
	rules := []model.CacheRule{
		{
			RuleName:      "忽略参数规则",
			RuleType:      3,
			RuleContent:   "/api.html",
			ParamType:     1, // 忽略参数
			CacheTime:     1000,
			Priority:      10,
			RequestMethod: "GET",
		},
		{
			RuleName:      "参数a=1规则",
			RuleType:      3,
			RuleContent:   "/api.html?a=1",
			ParamType:     2, // 完整参数
			CacheTime:     2000,
			Priority:      20,
			RequestMethod: "GET",
		},
		{
			RuleName:      "参数b=2规则",
			RuleType:      3,
			RuleContent:   "/api.html?b=2",
			ParamType:     2, // 完整参数
			CacheTime:     3000,
			Priority:      30,
			RequestMethod: "GET",
		},
		{
			RuleName:      "多参数a=1&b=2规则",
			RuleType:      3,
			RuleContent:   "/api.html?a=1&b=2",
			ParamType:     2, // 完整参数
			CacheTime:     4000,
			Priority:      40,
			RequestMethod: "GET",
		},
	}

	hostSafe := createTestHostSafe("test_host", rules)
	cacheConfig := createTestCacheConfig(1, "memory", "/tmp/cache")

	// 测试匹配a=1参数
	req1 := createTestRequest("GET", "http://example.com/api.html")
	req1.URL.RawQuery = "a=1"
	timeout1, err1 := checkCacheRule(hostSafe, cacheConfig, req1)
	if err1 != nil {
		t.Fatalf("具体参数值测试失败: %v", err1)
	}
	if timeout1 != 2000 {
		t.Fatalf("具体参数值测试返回的超时时间不正确，期望: 2000, 实际: %d", timeout1)
	}

	// 测试匹配b=2参数
	req2 := createTestRequest("GET", "http://example.com/api.html")
	req2.URL.RawQuery = "b=2"
	timeout2, err2 := checkCacheRule(hostSafe, cacheConfig, req2)
	if err2 != nil {
		t.Fatalf("具体参数值测试失败: %v", err2)
	}
	if timeout2 != 3000 {
		t.Fatalf("具体参数值测试返回的超时时间不正确，期望: 3000, 实际: %d", timeout2)
	}

	// 测试匹配多参数a=1&b=2
	req3 := createTestRequest("GET", "http://example.com/api.html")
	req3.URL.RawQuery = "a=1&b=2"
	timeout3, err3 := checkCacheRule(hostSafe, cacheConfig, req3)
	if err3 != nil {
		t.Fatalf("具体参数值测试失败: %v", err3)
	}
	if timeout3 != 4000 {
		t.Fatalf("具体参数值测试返回的超时时间不正确，期望: 4000, 实际: %d", timeout3)
	}

	// 测试参数顺序不同
	req4 := createTestRequest("GET", "http://example.com/api.html")
	req4.URL.RawQuery = "b=2&a=1"
	timeout4, err4 := checkCacheRule(hostSafe, cacheConfig, req4)
	if err4 != nil {
		t.Fatalf("参数顺序测试失败: %v", err4)
	}
	// 这里期望值取决于实现是否考虑参数顺序
	// 如果不考虑顺序，应该返回4000
	// 如果考虑顺序，应该返回1000（忽略参数规则）
	if timeout4 != 1000 {
		t.Fatalf("参数顺序测试返回的超时时间不正确，期望: 1000, 实际: %d", timeout4)
	}

	// 测试不匹配的参数
	req5 := createTestRequest("GET", "http://example.com/api.html")
	req5.URL.RawQuery = "c=3"
	timeout5, err5 := checkCacheRule(hostSafe, cacheConfig, req5)
	if err5 != nil {
		t.Fatalf("不匹配参数测试失败: %v", err5)
	}
	if timeout5 != 1000 {
		t.Fatalf("不匹配参数测试返回的超时时间不正确，期望: 1000, 实际: %d", timeout5)
	}

	// 测试额外参数
	req6 := createTestRequest("GET", "http://example.com/api.html")
	req6.URL.RawQuery = "a=1&b=2&c=3"
	timeout6, err6 := checkCacheRule(hostSafe, cacheConfig, req6)
	if err6 != nil {
		t.Fatalf("额外参数测试失败: %v", err6)
	}
	if timeout6 != 1000 {
		t.Fatalf("额外参数测试返回的超时时间不正确，期望: 1000, 实际: %d", timeout6)
	}
}

// 测试清理过期缓存文件
func TestCleanExpiredCache(t *testing.T) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "webcache_clean_test")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer cleanupTestEnv(tempDir)

	hostCode := "test_host"
	hostDir := filepath.Join(tempDir, hostCode)
	err = os.MkdirAll(hostDir, 0755)
	if err != nil {
		t.Fatalf("创建主机目录失败: %v", err)
	}

	// 创建一些测试文件
	now := time.Now().Unix()

	// 创建过期文件
	expiredKey := "expired_key"
	expiredTimestamp := now - 100 // 过期100秒
	expiredFilename := filepath.Join(hostDir, fmt.Sprintf("%s.%d.cache", expiredKey, expiredTimestamp))
	err = os.WriteFile(expiredFilename, []byte("expired content"), 0644)
	if err != nil {
		t.Fatalf("创建过期文件失败: %v", err)
	}

	// 创建未过期文件
	validKey := "valid_key"
	validTimestamp := now + 3600 // 1小时后过期
	validFilename := filepath.Join(hostDir, fmt.Sprintf("%s.%d.cache", validKey, validTimestamp))
	err = os.WriteFile(validFilename, []byte("valid content"), 0644)
	if err != nil {
		t.Fatalf("创建未过期文件失败: %v", err)
	}

	// 执行清理
	CleanExpiredCache(tempDir)

	// 验证过期文件已被删除
	if _, err := os.Stat(expiredFilename); !os.IsNotExist(err) {
		t.Fatalf("过期文件应该被删除")
	}

	// 验证未过期文件仍然存在
	if _, err := os.Stat(validFilename); os.IsNotExist(err) {
		t.Fatalf("未过期文件不应该被删除")
	}
}

// 测试目录不存在的情况
func TestCleanExpiredCacheNonExistentDir(t *testing.T) {
	// 使用一个不存在的目录
	nonExistentDir := "/tmp/non_existent_dir_" + strconv.FormatInt(time.Now().UnixNano(), 10)

	// 确保目录不存在
	if _, err := os.Stat(nonExistentDir); !os.IsNotExist(err) {
		t.Fatalf("测试目录不应该存在")
	}

	// 执行清理，应该不会出错
	CleanExpiredCache(nonExistentDir)
}

// 测试请求方法匹配
func TestRequestMethodMatching(t *testing.T) {
	// 测试空字符串（匹配所有方法）
	if !checkRequestMethod("GET", "") {
		t.Fatalf("空字符串应该匹配所有请求方法")
	}

	// 测试单个方法匹配
	if !checkRequestMethod("GET", "GET") {
		t.Fatalf("应该匹配相同的请求方法")
	}

	// 测试多个方法匹配
	if !checkRequestMethod("POST", "GET;POST;PUT") {
		t.Fatalf("应该匹配多个方法中的一个")
	}

	// 测试不匹配的方法
	if checkRequestMethod("DELETE", "GET;POST;PUT") {
		t.Fatalf("不应该匹配不在列表中的方法")
	}
}

// 测试后缀匹配
func TestSuffixMatching(t *testing.T) {
	// 测试空字符串
	if checkSuffixMatch("/test.jpg", "") {
		t.Fatalf("空字符串不应该匹配任何路径")
	}

	// 测试单个后缀匹配
	if !checkSuffixMatch("/test.jpg", ".jpg") {
		t.Fatalf("应该匹配正确的后缀")
	}

	// 测试多个后缀匹配
	if !checkSuffixMatch("/test.png", ".jpg;.png;.gif") {
		t.Fatalf("应该匹配多个后缀中的一个")
	}

	// 测试不匹配的后缀
	if checkSuffixMatch("/test.txt", ".jpg;.png;.gif") {
		t.Fatalf("不应该匹配不在列表中的后缀")
	}

	// 测试大小写不敏感
	if !checkSuffixMatch("/test.JPG", ".jpg") {
		t.Fatalf("后缀匹配应该不区分大小写")
	}
}

// 测试目录匹配
func TestDirectoryMatching(t *testing.T) {
	// 测试空字符串
	if checkDirectoryMatch("/static/test.jpg", "") {
		t.Fatalf("空字符串不应该匹配任何路径")
	}

	// 测试单个目录匹配
	if !checkDirectoryMatch("/static/test.jpg", "/static/") {
		t.Fatalf("应该匹配正确的目录前缀")
	}

	// 测试多个目录匹配
	if !checkDirectoryMatch("/assets/test.png", "/static/;/assets/;/images/") {
		t.Fatalf("应该匹配多个目录前缀中的一个")
	}

	// 测试不匹配的目录
	if checkDirectoryMatch("/uploads/test.jpg", "/static/;/assets/;/images/") {
		t.Fatalf("不应该匹配不在列表中的目录前缀")
	}

	// 测试大小写不敏感
	if !checkDirectoryMatch("/STATIC/test.jpg", "/static/") {
		t.Fatalf("目录匹配应该不区分大小写")
	}
}

// 测试文件匹配
func TestExactFileMatching(t *testing.T) {
	// 测试空字符串
	if checkExactFileMatch("/index.html", "") {
		t.Fatalf("空字符串不应该匹配任何文件")
	}

	// 测试单个文件匹配
	if !checkExactFileMatch("/index.html", "/index.html") {
		t.Fatalf("应该匹配完全相同的文件路径")
	}

	// 测试多个文件匹配
	if !checkExactFileMatch("/home.html", "/index.html;/home.html;/about.html") {
		t.Fatalf("应该匹配多个文件路径中的一个")
	}

	// 测试不匹配的文件
	if checkExactFileMatch("/contact.html", "/index.html;/home.html;/about.html") {
		t.Fatalf("不应该匹配不在列表中的文件路径")
	}

	// 测试大小写不敏感
	if !checkExactFileMatch("/INDEX.HTML", "/index.html") {
		t.Fatalf("文件匹配应该不区分大小写")
	}
}
