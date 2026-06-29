package utils

import (
	"testing"
	"time"
)

func TestValidatePasswordComplexity(t *testing.T) {
	full := PasswordComplexityPolicy{MinLength: 8, RequireUpper: true, RequireLower: true, RequireDigit: true, RequireSpecial: true}
	tests := []struct {
		name     string
		password string
		policy   PasswordComplexityPolicy
		wantOK   bool
		msgPart  string
	}{
		{"all satisfied", "MyPass123!", full, true, ""},
		{"too short", "Aa1!", full, false, "长度至少"},
		{"missing upper", "mypass123!", full, false, "大写"},
		{"missing lower", "MYPASS123!", full, false, "小写"},
		{"missing digit", "MyPassword!", full, false, "数字"},
		{"missing special", "MyPass1234", full, false, "特殊字符"},
		{"only length required - ok", "abcdefgh", PasswordComplexityPolicy{MinLength: 8}, true, ""},
		{"only length required - short", "abc", PasswordComplexityPolicy{MinLength: 8}, false, "长度至少"},
		{"no policy passes anything", "x", PasswordComplexityPolicy{}, true, ""},
		{"unicode length counted by rune", "密码密码密码密码", PasswordComplexityPolicy{MinLength: 8}, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, msg := ValidatePasswordComplexity(tt.password, tt.policy)
			if ok != tt.wantOK {
				t.Fatalf("ValidatePasswordComplexity(%q) ok = %v, want %v (msg=%q)", tt.password, ok, tt.wantOK, msg)
			}
			if !tt.wantOK && tt.msgPart != "" && !contains(msg, tt.msgPart) {
				t.Errorf("expected msg to contain %q, got %q", tt.msgPart, msg)
			}
		})
	}
}

func TestIsPasswordExpired(t *testing.T) {
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.Local)
	tests := []struct {
		name          string
		pwdUpdateTime string
		expireDays    int
		want          bool
	}{
		{"feature disabled (0 days)", "2020-01-01 00:00:00", 0, false},
		{"feature disabled (negative)", "2020-01-01 00:00:00", -1, false},
		{"empty time not tracked", "", 90, false},
		{"unparseable not tracked", "not-a-time", 90, false},
		{"not yet expired", "2026-06-01 12:00:00", 90, false},
		{"exactly boundary not expired", "2026-05-31 12:00:00", 29, false},
		{"expired", "2026-01-01 12:00:00", 90, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPasswordExpired(tt.pwdUpdateTime, tt.expireDays, now); got != tt.want {
				t.Errorf("IsPasswordExpired(%q, %d) = %v, want %v", tt.pwdUpdateTime, tt.expireDays, got, tt.want)
			}
		})
	}
}

func TestIsPasswordReused(t *testing.T) {
	history := []string{"hashA", "hashB", "hashC"}
	if !IsPasswordReused("hashB", history) {
		t.Error("expected hashB to be detected as reused")
	}
	if IsPasswordReused("hashX", history) {
		t.Error("expected hashX to be considered new")
	}
	if IsPasswordReused("anything", nil) {
		t.Error("empty history should never report reuse")
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
