package wafdefenserce

import (
	"regexp"
	"strings"
)

const btick = "\x60" // 反引号 `

// 通用 OS 命令注入检测：仅在"shell 元字符/替换语法 + 已知命令词"组合出现时判定。
// 关键防误报：命令词后紧跟 = 视为参数名(如 ?id=2)不判；反引号仅在独特命令或带参时判(避开 markdown `id`)；
// del/move/copy/format 这类常见词必须带 flag/通配/盘符才判(对齐 Linux 的 rm/mv)。
var (
	cmdAny      = `(?:id|whoami|uname|hostname|ifconfig|ipconfig|systeminfo|powershell|netcat|nc|nslookup|telnet|tftp|bash|sh|ksh|zsh|cat|ls|dir|pwd|env|type|head|tail|more|less|grep|find|curl|wget|ping|chmod|chown|cp|mv|rm|tasklist|netstat|certutil|bitsadmin|wmic)`
	cmdDistinct = `(?:whoami|uname|hostname|ifconfig|ipconfig|systeminfo|powershell|netcat|nslookup|telnet|tftp|bash|tasklist|taskkill|netstat|certutil|bitsadmin|wmic|schtasks|vssadmin|netsh|icacls|takeown|robocopy|xcopy|bcdedit|diskpart|wbadmin|fsutil)`
	cmdArg      = `(?:cat|ls|dir|type|pwd|env|cp|mv|rm|chmod|chown|head|tail|more|less|grep|find|uname|whoami|id|wget|curl|nc|ping|nslookup)`

	reSubstDollar    = regexp.MustCompile(`(?i)\$\(\s*` + cmdAny + `\b`)                                                                                                                                                                                                                        // $(cmd)
	reSubstBacktick  = regexp.MustCompile("(?i)" + btick + `\s*(?:` + cmdDistinct + `\b|` + cmdAny + `\s+\S)`)                                                                                                                                                                                  // `cmd`(独特或带参)
	reMetaCmd        = regexp.MustCompile("(?i)(?:;|&|\\||\\n|\\r)\\s*" + cmdDistinct + "(?:[\\s;|&)'\"" + btick + "]|$)")                                                                                                                                                                      // 元字符(含单 & Win分隔符)+独特命令
	reArgCmd         = regexp.MustCompile(`(?i)\b` + cmdArg + `\b\s+(?:-{1,2}[a-z]|/(?:etc|bin|usr|var|root|proc|sys|tmp|dev|home)\b|[a-z]:\\)`)                                                                                                                                                // 命令+路径/flag/盘符
	reBareId         = regexp.MustCompile(`(?i)(?:;|\|\||&&|\||\n|\r)\s*id(?:[;|&)]|$)`)                                                                                                                                                                                                        // 分隔符+裸 id(排除 =/空格)
	reWinSub         = regexp.MustCompile(`(?i)(?:\bnet\s+(?:user|localgroup|group|share|use|accounts|view|stop|start|pause|continue)\b|\breg\s+(?:add|query|delete|export|import|save)\b|\bsc\s+(?:create|config|query|start|stop|delete)\b|\bcmd(?:\.exe)?\s*/[ckq]|\bshutdown\s+[/-][a-z])`) // Win 常见词+子命令
	reWinDestructive = regexp.MustCompile(`(?i)(?:\b(?:del|erase|rd|rmdir|ren|rename|move|copy|attrib|cipher)\b\s+(?:/[a-z]|[a-z]:\\|\*|[+-][a-z])|\bformat\s+[a-z]:)`)                                                                                                                         // Win 破坏性命令+参数上下文
	rePwsh           = regexp.MustCompile(`(?i)(?:powershell(?:\.exe)?\s+-e(?:nc|ncodedcommand)?\b|\binvoke-expression\b|\biex\b\s*\(|\bdownloadstring\b|\bnet\.webclient\b|\binvoke-webrequest\b|\biwr\b\s+https?|\bremove-item\b|\bclear-content\b)`)                                         // PowerShell 执行/下载/删除
)

func DetermineRCE(args ...string) (bool, string) {
	if isRce, name := phpRCE(args...); isRce {
		return true, name
	}
	if isRce, name := osCmdInjection(args...); isRce {
		return true, name
	}
	return false, "未知"
}

func osCmdInjection(args ...string) (bool, string) {
	for _, arg := range args {
		if strings.TrimSpace(arg) == "" {
			continue
		}
		if reSubstDollar.MatchString(arg) || reSubstBacktick.MatchString(arg) ||
			reMetaCmd.MatchString(arg) || reArgCmd.MatchString(arg) || reBareId.MatchString(arg) ||
			reWinSub.MatchString(arg) || reWinDestructive.MatchString(arg) || rePwsh.MatchString(arg) {
			return true, "存在OS命令注入"
		}
	}
	return false, "未知"
}

func phpRCE(args ...string) (bool, string) {
	for _, arg := range args {
		if strings.Contains(arg, "phpinfo()") {
			return true, "存在PHP rce攻击"
		}
		if strings.Contains(arg, "call_user_func_array") {
			return true, "存在PHP rce攻击"
		}
		if strings.Contains(arg, "invokefunction") {
			return true, "存在PHP rce攻击"
		}
	}
	return false, "未知"
}
