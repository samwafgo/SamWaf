package utils

import (
	"SamWaf/global"
	"fmt"
	"strings"
	"time"
	"unicode"
)

// pwdTimeLayout 与 customtype.JsonTime 落库格式保持一致
const pwdTimeLayout = "2006-01-02 15:04:05"

// PasswordComplexityPolicy 口令复杂度策略
type PasswordComplexityPolicy struct {
	MinLength      int  // 最小长度
	RequireUpper   bool // 需大写字母
	RequireLower   bool // 需小写字母
	RequireDigit   bool // 需数字
	RequireSpecial bool // 需特殊字符
}

// ValidatePasswordComplexity 校验口令是否满足复杂度策略。
// 返回 (是否通过, 不通过原因)。这是纯函数，便于单测与各设密入口复用。
func ValidatePasswordComplexity(password string, policy PasswordComplexityPolicy) (bool, string) {
	if policy.MinLength > 0 && len([]rune(password)) < policy.MinLength {
		return false, fmt.Sprintf("密码长度至少 %d 位", policy.MinLength)
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case isSpecialChar(r):
			hasSpecial = true
		}
	}
	if policy.RequireUpper && !hasUpper {
		return false, "密码必须包含大写字母"
	}
	if policy.RequireLower && !hasLower {
		return false, "密码必须包含小写字母"
	}
	if policy.RequireDigit && !hasDigit {
		return false, "密码必须包含数字"
	}
	if policy.RequireSpecial && !hasSpecial {
		return false, "密码必须包含特殊字符"
	}
	return true, ""
}

// isSpecialChar 判断是否特殊字符（非字母数字、非空白的可见字符）
func isSpecialChar(r rune) bool {
	if unicode.IsLetter(r) || unicode.IsDigit(r) {
		return false
	}
	if unicode.IsSpace(r) {
		return false
	}
	return unicode.IsPunct(r) || unicode.IsSymbol(r)
}

// IsPasswordExpired 判断口令是否已过有效期。纯函数：
//   - expireDays <= 0：不启用有效期，永不过期
//   - pwdUpdateTime 为空或无法解析：视为未跟踪，按未过期处理（不锁死历史账号）
func IsPasswordExpired(pwdUpdateTime string, expireDays int, now time.Time) bool {
	if expireDays <= 0 {
		return false
	}
	pwdUpdateTime = strings.TrimSpace(pwdUpdateTime)
	if pwdUpdateTime == "" {
		return false
	}
	t, err := time.ParseInLocation(pwdTimeLayout, pwdUpdateTime, now.Location())
	if err != nil {
		return false
	}
	return now.After(t.AddDate(0, 0, expireDays))
}

// IsPasswordReused 判断新口令指纹是否命中历史指纹（防重用）。纯函数。
func IsPasswordReused(newHash string, history []string) bool {
	for _, h := range history {
		if h == newHash {
			return true
		}
	}
	return false
}

// BuildPolicyFromConfig 从全局配置组装当前口令复杂度策略
func BuildPolicyFromConfig() PasswordComplexityPolicy {
	return PasswordComplexityPolicy{
		MinLength:      int(global.GCONFIG_PWD_MIN_LENGTH),
		RequireUpper:   global.GCONFIG_PWD_REQUIRE_UPPER == 1,
		RequireLower:   global.GCONFIG_PWD_REQUIRE_LOWER == 1,
		RequireDigit:   global.GCONFIG_PWD_REQUIRE_DIGIT == 1,
		RequireSpecial: global.GCONFIG_PWD_REQUIRE_SPECIAL == 1,
	}
}
