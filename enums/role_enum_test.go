package enums

import "testing"

func TestIsValidRole(t *testing.T) {
	tests := []struct {
		role string
		want bool
	}{
		{ROLE_SUPER_ADMIN, true},
		{ROLE_SYSTEM_ADMIN, true},
		{ROLE_SECURITY_ADMIN, true},
		{ROLE_AUDIT_ADMIN, true},
		{"", false},
		{"admin", false},
		{"unknownRole", false},
	}
	for _, tt := range tests {
		t.Run(tt.role, func(t *testing.T) {
			if got := IsValidRole(tt.role); got != tt.want {
				t.Errorf("IsValidRole(%q) = %v, want %v", tt.role, got, tt.want)
			}
		})
	}
}

func TestNormalizeRole(t *testing.T) {
	tests := []struct {
		name string
		role string
		want string
	}{
		{"empty falls back to super", "", ROLE_SUPER_ADMIN},
		{"invalid falls back to super", "garbage", ROLE_SUPER_ADMIN},
		{"super kept", ROLE_SUPER_ADMIN, ROLE_SUPER_ADMIN},
		{"system kept", ROLE_SYSTEM_ADMIN, ROLE_SYSTEM_ADMIN},
		{"security kept", ROLE_SECURITY_ADMIN, ROLE_SECURITY_ADMIN},
		{"audit kept", ROLE_AUDIT_ADMIN, ROLE_AUDIT_ADMIN},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeRole(tt.role); got != tt.want {
				t.Errorf("NormalizeRole(%q) = %q, want %q", tt.role, got, tt.want)
			}
		})
	}
}

func TestIsSuperAdmin(t *testing.T) {
	for _, role := range []string{"", "garbage", ROLE_SUPER_ADMIN} {
		if !IsSuperAdmin(role) {
			t.Errorf("IsSuperAdmin(%q) = false, want true (empty/invalid should fall back to super)", role)
		}
	}
	for _, role := range []string{ROLE_SYSTEM_ADMIN, ROLE_SECURITY_ADMIN, ROLE_AUDIT_ADMIN} {
		if IsSuperAdmin(role) {
			t.Errorf("IsSuperAdmin(%q) = true, want false", role)
		}
	}
}

func TestAllRoles(t *testing.T) {
	roles := AllRoles()
	if len(roles) != 4 {
		t.Fatalf("AllRoles() len = %d, want 4", len(roles))
	}
	for _, r := range roles {
		if !IsValidRole(r) {
			t.Errorf("AllRoles() contains invalid role %q", r)
		}
	}
}
