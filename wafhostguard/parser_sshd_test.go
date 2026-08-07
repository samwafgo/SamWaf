package wafhostguard

import (
	"testing"
	"time"
)

// 样本全部取自真实 sshd 日志格式。这些用例是整个模块的地基：
// 解析错了会误封无辜 IP，解析漏了等于防护形同虚设。
func TestParseSSHDLine(t *testing.T) {
	now := time.Now()

	cases := []struct {
		name     string
		line     string
		wantOK   bool
		wantIP   string
		wantUser string
		wantPort int
		wantKind FailKind
		wantHard bool
	}{
		// —— 传统 syslog 行首(不带年份) ——
		{
			name:     "密码失败-存在的用户",
			line:     "Aug  6 14:55:01 myhost sshd[12345]: Failed password for root from 1.2.3.4 port 51234 ssh2",
			wantOK:   true,
			wantIP:   "1.2.3.4",
			wantUser: "root",
			wantPort: 51234,
			wantKind: FailPassword,
			wantHard: true,
		},
		{
			name:     "密码失败-不存在的用户",
			line:     "Aug  6 14:55:02 myhost sshd[12346]: Failed password for invalid user admin from 5.6.7.8 port 40001 ssh2",
			wantOK:   true,
			wantIP:   "5.6.7.8",
			wantUser: "admin",
			wantPort: 40001,
			wantKind: FailPassword,
			wantHard: true,
		},
		{
			name:     "公钥失败",
			line:     "Aug  6 14:55:03 myhost sshd[12347]: Failed publickey for git from 9.9.9.9 port 33333 ssh2: RSA SHA256:xxxx",
			wantOK:   true,
			wantIP:   "9.9.9.9",
			wantUser: "git",
			wantPort: 33333,
			wantKind: FailPublicKey,
			wantHard: true,
		},
		{
			name:     "keyboard-interactive 归为密码类",
			line:     "Aug  6 14:55:04 myhost sshd[12348]: Failed keyboard-interactive/pam for invalid user test from 2.2.2.2 port 111 ssh2",
			wantOK:   true,
			wantIP:   "2.2.2.2",
			wantUser: "test",
			wantPort: 111,
			wantKind: FailPassword,
			wantHard: true,
		},
		{
			name:     "单连接内超过最大尝试次数",
			line:     "Aug  6 14:55:05 myhost sshd[12349]: error: maximum authentication attempts exceeded for root from 3.3.3.3 port 22222 ssh2 [preauth]",
			wantOK:   true,
			wantIP:   "3.3.3.3",
			wantUser: "root",
			wantPort: 22222,
			wantKind: FailMaxAuthTries,
			wantHard: true,
		},
		{
			name:     "被 AllowUsers 挡下",
			line:     "Aug  6 14:55:06 myhost sshd[12350]: User root from 4.4.4.4 not allowed because not listed in AllowUsers",
			wantOK:   true,
			wantIP:   "4.4.4.4",
			wantUser: "root",
			wantKind: FailNotAllowed,
			wantHard: true,
		},

		// —— 软失败：解析得出来，但默认不计入阈值 ——
		{
			name:     "用户名枚举(软失败，会与Failed password成对出现)",
			line:     "Aug  6 14:55:07 myhost sshd[12351]: Invalid user oracle from 6.6.6.6 port 5555",
			wantOK:   true,
			wantIP:   "6.6.6.6",
			wantUser: "oracle",
			wantPort: 5555,
			wantKind: FailInvalidUser,
			wantHard: false,
		},
		{
			name:     "PAM认证失败(软失败)",
			line:     "Aug  6 14:55:08 myhost sshd[12352]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=7.7.7.7  user=root",
			wantOK:   true,
			wantIP:   "7.7.7.7",
			wantUser: "root",
			wantKind: FailPamAuth,
			wantHard: false,
		},
		{
			name:     "preauth断连(软失败，扫描器高发)",
			line:     "Aug  6 14:55:09 myhost sshd[12353]: Connection closed by authenticating user root 8.8.8.8 port 44444 [preauth]",
			wantOK:   true,
			wantIP:   "8.8.8.8",
			wantUser: "root",
			wantPort: 44444,
			wantKind: FailPreauthClose,
			wantHard: false,
		},
		{
			name:     "preauth重置(软失败)",
			line:     "Aug  6 14:55:10 myhost sshd[12354]: Connection reset by 10.20.30.40 port 44445 [preauth]",
			wantOK:   true,
			wantIP:   "10.20.30.40",
			wantPort: 44445,
			wantKind: FailPreauthClose,
			wantHard: false,
		},
		{
			name:     "Disconnected preauth(软失败)",
			line:     "Aug  6 14:55:11 myhost sshd[12355]: Disconnected from invalid user ubnt 11.22.33.44 port 44446 [preauth]",
			wantOK:   true,
			wantIP:   "11.22.33.44",
			wantUser: "ubnt",
			wantPort: 44446,
			wantKind: FailPreauthClose,
			wantHard: false,
		},

		// —— IPv6 ——
		{
			name:     "IPv6 密码失败",
			line:     "Aug  6 14:55:12 myhost sshd[12356]: Failed password for root from 2001:db8::1 port 51234 ssh2",
			wantOK:   true,
			wantIP:   "2001:db8::1",
			wantUser: "root",
			wantPort: 51234,
			wantKind: FailPassword,
			wantHard: true,
		},
		{
			name:     "IPv4-mapped IPv6",
			line:     "Aug  6 14:55:13 myhost sshd[12357]: Failed password for root from ::ffff:1.2.3.4 port 51235 ssh2",
			wantOK:   true,
			wantIP:   "::ffff:1.2.3.4",
			wantUser: "root",
			wantPort: 51235,
			wantKind: FailPassword,
			wantHard: true,
		},

		// —— RFC5424 行首 ——
		{
			name:     "RFC5424行首",
			line:     "2026-08-06T14:55:14.123456+08:00 myhost sshd 12358 - - Failed password for root from 12.13.14.15 port 51236 ssh2",
			wantOK:   true,
			wantIP:   "12.13.14.15",
			wantUser: "root",
			wantPort: 51236,
			wantKind: FailPassword,
			wantHard: true,
		},

		// —— journalctl -o cat：没有行首 ——
		{
			name:     "journalctl无行首",
			line:     "Failed password for invalid user postgres from 16.17.18.19 port 51237 ssh2",
			wantOK:   true,
			wantIP:   "16.17.18.19",
			wantUser: "postgres",
			wantPort: 51237,
			wantKind: FailPassword,
			wantHard: true,
		},

		// —— 必须被丢弃的 ——
		{
			name:   "非法IP(日志被截断)整行丢弃",
			line:   "Aug  6 14:55:15 myhost sshd[12359]: Failed password for root from 1.2.3 port 51238 ssh2",
			wantOK: false,
		},
		{
			name:   "rhost是域名而非IP，丢弃",
			line:   "Aug  6 14:55:16 myhost sshd[12360]: pam_unix(sshd:auth): authentication failure; rhost=evil.example.com  user=root",
			wantOK: false,
		},
		{
			name:   "登录成功不是失败",
			line:   "Aug  6 14:55:17 myhost sshd[12361]: Accepted password for root from 1.2.3.4 port 51239 ssh2",
			wantOK: false,
		},
		{
			name:   "已认证连接的正常关闭(无preauth)不算失败",
			line:   "Aug  6 14:55:18 myhost sshd[12362]: Connection closed by 1.2.3.4 port 51240",
			wantOK: false,
		},
		{
			name:   "无关日志行",
			line:   "Aug  6 14:55:19 myhost systemd[1]: Started Session 123 of user root.",
			wantOK: false,
		},
		{
			name:   "空行",
			line:   "",
			wantOK: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev, ok := ParseSSHDLine(c.line, now)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v (ev=%+v)", ok, c.wantOK, ev)
			}
			if !c.wantOK {
				return
			}
			if ev.IP != c.wantIP {
				t.Errorf("IP = %q, want %q", ev.IP, c.wantIP)
			}
			if ev.User != c.wantUser {
				t.Errorf("User = %q, want %q", ev.User, c.wantUser)
			}
			if ev.Port != c.wantPort {
				t.Errorf("Port = %d, want %d", ev.Port, c.wantPort)
			}
			if ev.Kind != c.wantKind {
				t.Errorf("Kind = %q, want %q", ev.Kind, c.wantKind)
			}
			if ev.Kind.IsHard() != c.wantHard {
				t.Errorf("IsHard() = %v, want %v", ev.Kind.IsHard(), c.wantHard)
			}
			if ev.Source != SourceSSH {
				t.Errorf("Source = %q, want %q", ev.Source, SourceSSH)
			}
		})
	}
}

func TestParseSSHDListenPort(t *testing.T) {
	cases := []struct {
		line string
		want int
	}{
		{"Aug  6 14:00:00 myhost sshd[1]: Server listening on 0.0.0.0 port 22.", 22},
		{"Aug  6 14:00:00 myhost sshd[1]: Server listening on :: port 22222.", 22222},
		{"Aug  6 14:00:00 myhost sshd[1]: Failed password for root from 1.2.3.4 port 51234 ssh2", 0},
		{"", 0},
	}
	for _, c := range cases {
		if got := ParseSSHDListenPort(c.line); got != c.want {
			t.Errorf("ParseSSHDListenPort(%q) = %d, want %d", c.line, got, c.want)
		}
	}
}

// TruncRaw 必须真的截断，否则超长日志行会把事件表撑爆
func TestTruncRaw(t *testing.T) {
	long := make([]byte, RawLimit+100)
	for i := range long {
		long[i] = 'a'
	}
	if got := len(TruncRaw(string(long))); got != RawLimit {
		t.Errorf("len = %d, want %d", got, RawLimit)
	}
	if got := TruncRaw("short"); got != "short" {
		t.Errorf("got %q, want %q", got, "short")
	}
}
