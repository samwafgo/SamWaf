package enums

// 账号角色（三权分立 + 超级管理员兜底）
// 国标 GB/T 32917 §7「自身安全」要求权限分离，这里定义四类角色：
//   - superAdmin   超级管理员：拥有全部权限，向后兼容历史单一账号、用于初始部署
//   - systemAdmin  系统管理员：账户管理 + 系统配置
//   - securityAdmin 安全管理员：WAF 策略/规则/防护配置
//   - auditAdmin   审计管理员：日志审计（只读），独立审计系统员与安全员，三者相互制约
const (
	ROLE_SUPER_ADMIN    = "superAdmin"    // 超级管理员
	ROLE_SYSTEM_ADMIN   = "systemAdmin"   // 系统管理员
	ROLE_SECURITY_ADMIN = "securityAdmin" // 安全管理员
	ROLE_AUDIT_ADMIN    = "auditAdmin"    // 审计管理员
)

// AllRoles 返回全部合法角色
func AllRoles() []string {
	return []string{ROLE_SUPER_ADMIN, ROLE_SYSTEM_ADMIN, ROLE_SECURITY_ADMIN, ROLE_AUDIT_ADMIN}
}

// IsValidRole 判断角色字符串是否合法
func IsValidRole(role string) bool {
	switch role {
	case ROLE_SUPER_ADMIN, ROLE_SYSTEM_ADMIN, ROLE_SECURITY_ADMIN, ROLE_AUDIT_ADMIN:
		return true
	default:
		return false
	}
}

// NormalizeRole 归一化角色：空角色（历史账号、未赋角色）一律视为超级管理员，
// 保证向后兼容——绝不因为引入 RBAC 把现网已存在账号锁死。
// 非法角色同样兜底为超级管理员，避免误降权后无人可管理。
func NormalizeRole(role string) string {
	if role == "" {
		return ROLE_SUPER_ADMIN
	}
	if !IsValidRole(role) {
		return ROLE_SUPER_ADMIN
	}
	return role
}

// IsSuperAdmin 是否超级管理员（含空角色兜底）
func IsSuperAdmin(role string) bool {
	return NormalizeRole(role) == ROLE_SUPER_ADMIN
}
