package wafdefenserce

import "testing"

func TestOsCmdInjection_Detects(t *testing.T) {
	attacks := []string{
		";id",
		"|whoami",
		"&& cat /etc/passwd",
		"$(id)",
		"|| ls -la",
		";uname -a",
		"\nid",
		"`whoami`",
		"`cat /etc/passwd`",
		"q=abc;id",
		"127.0.0.1; cat /etc/passwd",
		"foo|nslookup",
		"data && rm -rf /tmp/x",
		"x=1|ipconfig",
	}
	for _, a := range attacks {
		if ok, _ := DetermineRCE(a); !ok {
			t.Errorf("应判定为命令注入但漏过: %q", a)
		}
	}
}

func TestOsCmdInjection_NoFalsePositive(t *testing.T) {
	benign := []string{
		"id=5&type=news&cat=tech",       // 参数名 id/type/cat
		"a=1;id=2",                      // ;id 后紧跟 = (参数)
		"item; id 5",                    // 散文里的 "; id 5"
		"the `id` field is required",    // markdown 反引号裸词
		"category=books",                // cat 是 category 一部分
		"best price 2024 & summer sale", // 单个 &
		"please SELECT your product",
		"drop me an email anytime",
		"O'Brien",
		"prove that 1=1 always holds",
		"run ls in the folder", // ls 后不是 flag/路径
		"how to access the admin panel",
		"content-type: application/json",
		"controls and settings", // 含 ls 但非 \bls\b
		"performance metrics",   // 含 rm? 无
		"",
	}
	for _, b := range benign {
		if ok, name := DetermineRCE(b); ok {
			t.Errorf("正常输入被误判为命令注入: %q (%s)", b, name)
		}
	}
}

func TestPhpRCE_StillWorks(t *testing.T) {
	if ok, _ := DetermineRCE("a=phpinfo()"); !ok {
		t.Error("phpinfo() 应仍被检测")
	}
}

func TestOsCmdInjection_Windows(t *testing.T) {
	// 全部为主机无害的只读侦察串（见 Payload/2026-08-20-命令注入Windows）
	attacks := []string{
		`& whoami`,
		`; systeminfo`,
		`| tasklist`,
		`& netstat -ano`,
		`& certutil`,
		`& bitsadmin`,
		`& wmic os get caption`,
		`& net user`,
		`& reg query HKLM`,
		`& sc query`,
		`& cmd /c whoami`,
		`; powershell -enc AAAA`,
		`x;iex(1)`,
		`foo invoke-expression bar`,
		`obj.downloadstring(u)`,
	}
	for _, a := range attacks {
		if ok, _ := DetermineRCE(a); !ok {
			t.Errorf("Windows 命令注入应判定但漏过: %q", a)
		}
	}
}

func TestOsCmdInjection_WindowsNoFalsePositive(t *testing.T) {
	benign := []string{
		`id=5&type=news&cat=tech`,
		`internet user guide`,
		`net income statement`,
		`region add-on available`,
		`misc query builder`,
		`download the report`,
		`please select cmd option`,
	}
	for _, b := range benign {
		if ok, name := DetermineRCE(b); ok {
			t.Errorf("正常输入被误判(Win): %q (%s)", b, name)
		}
	}
}

func TestOsCmdInjection_WinDestructive(t *testing.T) {
	// 全部无害形式(临时/不存在目标、shutdown /a=取消、独特工具只读)——见 Payload/命令注入Windows v2
	attacks := []string{
		`& del /f /q *.tmp`,
		`& erase /f poc.tmp`,
		`& rd /s /q pocdir`,
		`& rmdir /s /q pocdir`,
		`& move /y a.tmp b.tmp`,
		`& copy /y a.tmp b.tmp`,
		`format z:`,
		`& attrib +h poc.tmp`,
		`& cipher /w:pocdir`,
		`& xcopy /s a b`,
		`& robocopy a b /mir`,
		`& takeown /f poc.tmp`,
		`& icacls poc.tmp /grant everyone:F`,
		`& taskkill /im notepad.exe`,
		`& net stop w32time`,
		`& sc stop w32time`,
		`& shutdown /a`,
		`& vssadmin`,
		`& wbadmin get status`,
		`& bcdedit /enum`,
		`& diskpart`,
		`& fsutil fsinfo drives`,
		`; powershell Remove-Item -Recurse -Force pocdir`,
		`; powershell Clear-Content poc.tmp`,
	}
	for _, a := range attacks {
		if ok, _ := DetermineRCE(a); !ok {
			t.Errorf("Windows 破坏性命令应判定但漏过: %q", a)
		}
	}
}

func TestOsCmdInjection_WinDestructiveNoFP(t *testing.T) {
	benign := []string{
		`please move to the next page`,
		`copy the report to your inbox`,
		`format the document nicely`,
		`3rd floor office`,
		`children love the park`,
		`model number is 5`,
		`attribute the quote correctly`,
		`select del from the menu`,
		`net income grew this year`,
	}
	for _, b := range benign {
		if ok, name := DetermineRCE(b); ok {
			t.Errorf("正常输入被误判(Win破坏性): %q (%s)", b, name)
		}
	}
}
