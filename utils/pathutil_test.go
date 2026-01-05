package utils

import (
	"strings"
	"testing"
)

func TestGenerateRandomPathPrefix(t *testing.T) {
	// 测试生成10次，确保每次都不同
	paths := make(map[string]bool)
	for i := 0; i < 10; i++ {
		path := GenerateRandomPathPrefix()

		// 检查格式
		if !strings.HasPrefix(path, "/_waf_") {
			t.Errorf("生成的路径格式不正确: %s", path)
		}

		// 检查长度（/_waf_ = 6字符 + 至少8字符）
		if len(path) < 14 {
			t.Errorf("生成的路径长度不够: %s (长度: %d)", path, len(path))
		}

		// 检查是否唯一
		if paths[path] {
			t.Errorf("生成了重复的路径: %s", path)
		}
		paths[path] = true

		t.Logf("生成的路径: %s", path)
	}
}

func TestValidatePathPrefix(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"有效路径1", "/_waf_a7k3m9x2", true},
		{"有效路径2", "/_waf_test123", true},
		{"有效路径3", "/_custom_path", true},
		{"空字符串", "", false},
		{"不以/_开头", "/waf_test", false},
		{"长度太短", "/_waf", false},
		{"包含大写字母", "/_WAF_test", false},
		{"包含特殊字符", "/_waf_test@123", false},
		{"包含空格", "/_waf test", false},
		{"包含点号", "/_waf_test.abc", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidatePathPrefix(tt.path)
			if result != tt.expected {
				t.Errorf("ValidatePathPrefix(%s) = %v, expected %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestGetCaptchaPathOrDefault(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"空字符串返回默认值", "", "/samwaf_captcha"},
		{"有值返回原值", "/_waf_test", "/_waf_test"},
		{"自定义路径", "/_custom", "/_custom"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetCaptchaPathOrDefault(tt.input)
			if result != tt.expected {
				t.Errorf("GetCaptchaPathOrDefault(%s) = %s, expected %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGetHttpAuthPathOrDefault(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"空字符串返回默认值", "", "/samwaf_httpauth"},
		{"有值返回原值", "/_waf_auth", "/_waf_auth"},
		{"自定义路径", "/_login", "/_login"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetHttpAuthPathOrDefault(tt.input)
			if result != tt.expected {
				t.Errorf("GetHttpAuthPathOrDefault(%s) = %s, expected %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"正常路径", "/test/path", "/test/path"},
		{"末尾有斜杠", "/test/path/", "/test/path"},
		{"开头无斜杠", "test/path", "/test/path"},
		{"两端都有问题", "test/path/", "/test/path"},
		{"带空格", "  /test/path  ", "/test/path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizePath(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizePath(%s) = %s, expected %s", tt.input, result, tt.expected)
			}
		})
	}
}
