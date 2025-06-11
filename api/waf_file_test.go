package api

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// 响应结构体定义
type WafFileResponse struct {
	Code int             `json:"code"`
	Data json.RawMessage `json:"data"`
	Msg  string          `json:"msg"`
}

type FileListData struct {
	Files []map[string]interface{} `json:"files"`
	Total int                      `json:"total"`
}

// TestCanDeleteFile 测试文件删除权限判断
func TestCanDeleteFile(t *testing.T) {
	api := &WafFileApi{}

	testCases := []struct {
		fileName string
		relPath  string
		expected bool
		desc     string
	}{
		{"local_log.db", "local_log.db", true, "local_log文件应该可以删除"},
		{"local_log_backup.db", "backup/local_log_backup.db", true, "local_log备份文件应该可以删除"},
		{"local.db", "local.db", false, "主数据库文件不应该删除"},
		{"local_stats.db", "local_stats.db", false, "统计数据库文件不应该删除"},
		{"test.log", "logs/test.log", false, "普通日志文件不应该删除"},
		{"cache.tmp", "temp/cache.tmp", false, "临时文件不应该删除"},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			result := api.canDeleteFile(tc.fileName, tc.relPath)
			if result != tc.expected {
				t.Errorf("%s: 期望 %v，实际 %v", tc.desc, tc.expected, result)
			}
		})
	}
}

// TestGetFileDescription 测试文件描述获取
func TestGetFileDescription(t *testing.T) {
	api := &WafFileApi{}

	testCases := []struct {
		fileName string
		relPath  string
		expected string
		desc     string
	}{
		{"local.db", "local.db", "主数据库文件，存储WAF配置和规则", "主数据库文件描述"},
		{"local_stats.db", "local_stats.db", "统计数据库文件，存储访问统计信息", "统计数据库文件描述"},
		{"local_log.db", "local_log.db", "日志数据库文件，存储访问日志和攻击记录", "日志数据库文件描述"},
		{"backup.db", "backup/backup.db", "数据库备份文件", "备份文件描述"},
		{"rule.conf", "owasp/rule.conf", "OWASP规则集文件", "OWASP文件描述"},
		{"captcha.png", "captcha/captcha.png", "验证码相关文件", "验证码文件描述"},
		{"cert.crt", "ssl/cert.crt", "SSL证书文件", "SSL证书文件描述"},
		{"ip2region.xdb", "ip2region.xdb", "IP地理位置数据库", "IP数据库文件描述"},
		{"unknown.txt", "unknown.txt", "数据文件", "未知文件类型描述"},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			result := api.getFileDescription(tc.fileName, tc.relPath)
			if result != tc.expected {
				t.Errorf("%s: 期望 '%s'，实际 '%s'", tc.desc, tc.expected, result)
			}
		})
	}
}

// TestFormatFileSize 测试文件大小格式化
func TestFormatFileSize(t *testing.T) {
	api := &WafFileApi{}

	testCases := []struct {
		size     int64
		expected string
		desc     string
	}{
		{512, "512 B", "字节级别"},
		{1024, "1.0 KB", "1KB"},
		{1536, "1.5 KB", "1.5KB"},
		{1048576, "1.0 MB", "1MB"},
		{1073741824, "1.0 GB", "1GB"},
		{2147483648, "2.0 GB", "2GB"},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			result := api.formatFileSize(tc.size)
			if result != tc.expected {
				t.Errorf("%s: 期望 '%s'，实际 '%s'", tc.desc, tc.expected, result)
			}
		})
	}
}

// setupTestDataDir 创建测试用的data目录结构
func setupTestDataDir(t *testing.T) string {
	// 创建临时目录
	tempDir, err := ioutil.TempDir("", "samwaf_test_data")
	if err != nil {
		t.Fatalf("创建临时目录失败：%v", err)
	}

	// 创建测试文件
	testFiles := []struct {
		path    string
		content string
	}{
		{"local.db", "test database content"},
		{"local_log.db", "test log database content"},
		{"local_stats.db", "test stats database content"},
		{"backup/backup_20240101.db", "backup content"},
		{"owasp/rules.conf", "owasp rules"},
		{"captcha/image.png", "captcha image data"},
		{"ssl/cert.crt", "certificate content"},
		{"logs/app.log", "application logs"},
	}

	for _, file := range testFiles {
		filePath := filepath.Join(tempDir, file.path)
		dir := filepath.Dir(filePath)

		// 创建目录
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("创建目录失败 %s: %v", dir, err)
		}

		// 创建文件
		if err := ioutil.WriteFile(filePath, []byte(file.content), 0644); err != nil {
			t.Fatalf("创建文件失败 %s: %v", filePath, err)
		}
	}

	return tempDir
}

// cleanupTestDataDir 清理测试目录
func cleanupTestDataDir(tempDir string) {
	os.RemoveAll(tempDir)
}

// BenchmarkGetDataFilesApi 性能测试
func BenchmarkGetDataFilesApi(b *testing.B) {
	// 创建测试目录
	tempDir := setupTestDataDirForBench(b)
	defer cleanupTestDataDir(tempDir)

	// 创建Gin引擎
	r := gin.Default()
	r.GET("/samwaf/file/data_files", new(WafFileApi).GetDataFilesApi)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest(http.MethodGet, "/samwaf/file/data_files", nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
	}
}

// setupTestDataDirForBench 为性能测试创建更多文件
func setupTestDataDirForBench(b *testing.B) string {
	tempDir, err := ioutil.TempDir("", "samwaf_bench_data")
	if err != nil {
		b.Fatalf("创建临时目录失败：%v", err)
	}

	// 创建更多测试文件用于性能测试
	for i := 0; i < 100; i++ {
		filePath := filepath.Join(tempDir, fmt.Sprintf("test_file_%d.log", i))
		if err := ioutil.WriteFile(filePath, []byte("test content"), 0644); err != nil {
			b.Fatalf("创建文件失败 %s: %v", filePath, err)
		}
	}

	return tempDir
}
