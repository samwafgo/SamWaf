package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/utils"
	"SamWaf/wafacme"
	"bytes"
	"io"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

// ACME(HTTP-01) 校验请求的处理，分两层：
//
//	第一层 tryServeACMEChallenge —— 请求侧快速通道，排在所有检测之前。
//	         本地有挑战文件就直接应答，永不回源。
//	第二层 handleACMEChallengeResponse —— 回源之后的兜底，本地有文件就覆盖后端响应。
//
// 为什么要两层：CA 的校验请求会因为各种与证书无关的原因失败——后端 5xx/不可达、
// 被站点自己的地区限制/威胁情报IP/CC 拦截、后端对该路径抢答 200、
// 甚至后端响应里带了个 Accept-Ranges: bytes 让整段兜底被判成"静态资源"跳过（真实工单）。
// 第一层把绝大多数情况挡在前面，第二层兜住第一层没命中的残余。
//
// 安全上的第一硬约束：命中即由 WAF 自答并 return，**永不回源**；
// 未命中则**完整回落**原有检测链路，不跳过任何检测、不透传后端。
// 一旦写成"命中前缀就跳过检测转发后端"，这个前缀就成了万能绕过原语。

// isACMEChallengePath 判断是否是 ACME(HTTP-01) 证书校验请求。
//
// cleanPath 必须是已经 path.Clean + 转小写的路径，rawPath 是原始的 r.URL.Path。
// 两个参数缺一不可：
//   - 只看 rawPath：/.well-known/acme-challenge/../../admin 会命中前缀被放行，
//     而点号段原样转发给后端，后端按 RFC 3986 归一化成 /admin —— 整个网关就废了
//   - 只看 cleanPath：/foo/../.well-known/acme-challenge/x 归一化后会命中前缀，
//     虽然目标确实落在 challenge 目录里，但这种写法只可能是刻意构造的探测
//
// 抽成独立函数是为了让回归测试能直接钉住这个判定本身，
// 而不是去测 path.Clean 的语义——后者即使有人把实现改回 rawPath 也照样是绿的。
func isACMEChallengePath(cleanPath, rawPath string) bool {
	if strings.Contains(rawPath, "..") {
		return false
	}
	return strings.HasPrefix(cleanPath, strings.ToLower(global.GSSL_HTTP_CHANGLE_PATH))
}

// acmeChallengeToken 从请求里取出合法的挑战 token，取不到返回空串。
//
// 判定顺序是刻意排的：全部是纯 CPU 的字符串/正则操作，排在任何磁盘或内存表访问之前。
// /.well-known/ 是互联网上被扫烂的路径，非法请求必须在最便宜的地方就被打掉。
func acmeChallengeToken(r *http.Request) string {
	// CA 只会用 GET（HEAD 容错），其余方法一律不是校验请求
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return ""
	}
	cleanPath := strings.ToLower(path.Clean(r.URL.Path))
	if !isACMEChallengePath(cleanPath, r.URL.Path) {
		return ""
	}
	// 用 Base 而不是按 "/" 切成固定 4 段：带多余斜杠、层级不符的变体都能被正确处理，
	// 且不会像固定切分那样在不匹配时静默什么都不做
	token := path.Base(r.URL.Path)
	if !utils.IsValidChallengeFile(token) {
		return ""
	}
	return token
}

// loadChallengeContent 取挑战文件内容，两层来源：内存注册表 → 磁盘。
//
// 防刷的闸门全在这里：
//  1. 门闩关闭（没有进行中的挑战）时立即返回，一次系统调用都不做 —— 99.99% 的时间都是这条路径
//  2. 内存注册表命中即返回，O(1) 且无系统调用
//  3. 只有"门闩开着但内存没有"才会读盘，而这只在蓝绿升级双 Worker 并存时才正常发生，
//     所以额外加了每秒读盘次数上限
func loadChallengeContent(hostCode, token string) (string, bool) {
	if !wafacme.GateOpen() {
		return "", false
	}
	if keyAuth, ok := wafacme.Lookup(hostCode, token); ok {
		return keyAuth, true
	}
	if !wafacme.AllowDiskRead() {
		return "", false
	}
	return readChallengeFile(hostCode, token)
}

// challengeFileOpen 是唯一的挑战文件打开入口，抽成变量是为了让测试能替换它，
// 直接断言"门闩关闭时一次磁盘 IO 都不发生"——这是防刷设计的核心，
// 用行为断言（返回值）替代不了，必须数真实的打开次数。
var challengeFileOpen = os.Open

// readChallengeFile 读磁盘上的挑战文件。
// 路径由 acmeChallengeFilePath 统一拼装，token 已经过白名单校验，不存在穿越空间。
func readChallengeFile(hostCode, token string) (string, bool) {
	filePath := acmeChallengeFilePath(hostCode, token)
	f, err := challengeFileOpen(filePath)
	if err != nil {
		return "", false
	}
	defer f.Close()

	// 限长读取：真实 keyAuth 只有 87 字节左右，
	// 设上限是为了万一那个目录被塞进大文件时不至于整块读进内存
	buf, err := io.ReadAll(io.LimitReader(f, wafacme.MaxChallengeFileSize()))
	if err != nil {
		return "", false
	}
	content := string(buf)
	if content == "" {
		return "", false
	}
	return content, true
}

// tryServeACMEChallenge 请求侧快速通道。命中返回 true（调用方必须立即返回，不得继续处理）。
//
// 挂载点在 ServeHTTP 里"站点匹配完成、weblogbean 就绪之后的第一处"，
// 即黑名单/CC/规则/AI/OWASP/统一访问认证/静态站点/缓存等全部检测之前。
// 位置必须这么靠前：CA 会从全球多个出口发起校验，很容易撞上地区限制或威胁情报IP，
// 一旦被拦成 403，请求根本走不到回源，第二层兜底也就无从谈起。
func (waf *WafEngine) tryServeACMEChallenge(w http.ResponseWriter, r *http.Request, weblogbean *innerbean.WebLog) bool {
	token := acmeChallengeToken(r)
	if token == "" {
		return false
	}

	content, ok := loadChallengeContent(weblogbean.HOST_CODE, token)
	if !ok {
		// 本地没有这个挑战文件：可能是扫描器，也可能是用户自己在后端跑 certbot。
		// 一律回落原链路，让后续检测和回源照常进行——这里绝不能"放行到后端"。
		return false
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(content))
	}

	weblogbean.ACTION = "放行"
	weblogbean.STATUS = http.StatusText(http.StatusOK)
	weblogbean.STATUS_CODE = http.StatusOK
	weblogbean.RULE = "ACME证书校验"
	weblogbean.TASK_FLAG = 1
	weblogbean.TimeSpent = time.Now().UnixNano()/1e6 - weblogbean.UNIX_ADD_TIME
	global.GQEQUE_LOG_DB.Enqueue(weblogbean)

	infoACMEChallengeHit(weblogbean.HOST, weblogbean.HOST_CODE, weblogbean.URL,
		acmeChallengeFilePath(weblogbean.HOST_CODE, token), 0)
	return true
}

// handleACMEChallengeResponse 响应侧兜底。
//
// 返回 true 表示"这是一个 ACME 校验请求，已按证书校验的规则处理完毕"，
// 调用方据此跳过常规的响应处理分支（自定义错误页等）。
//
// 这个函数必须与 isStaticAssist 判定**并列**而不是嵌套在它内部：
// "是不是静态资源"和"是不是证书校验路径"毫不相干，
// 而后端只要回一个带 Accept-Ranges: bytes 的响应（IIS、Apache 的 ErrorDocument 静态错误页
// 都会带），isStaticAssist 就为真，整段兜底连同日志会被一起吞掉——
// 表现为"证书签不下来，而且日志里什么都没有"，这正是线上真实工单的成因。
func handleACMEChallengeResponse(resp *http.Response, weblogfrist *innerbean.WebLog, backendCheckStart int64) bool {
	if !strings.HasPrefix(weblogfrist.URL, global.GSSL_HTTP_CHANGLE_PATH) {
		return false
	}

	weblogfrist.TimeSpent = time.Now().UnixNano()/1e6 - weblogfrist.UNIX_ADD_TIME
	zlog.Info("acme-challenge", weblogfrist.HOST, weblogfrist.URL)

	token := acmeTokenFromURL(weblogfrist.URL)
	if token == "" {
		warnACMEChallenge(weblogfrist.HOST, weblogfrist.HOST_CODE, weblogfrist.URL, "", "", resp.StatusCode,
			"URL 不是标准的挑战路径或 token 不合法，未尝试本地校验文件",
			"标准路径形如 /.well-known/acme-challenge/<token>；多为扫描器请求，可忽略")
		return true
	}
	filePath := acmeChallengeFilePath(weblogfrist.HOST_CODE, token)

	// 本地有挑战文件就一定用它，与后端返回什么状态码无关。
	//
	// 老实现是"后端返回 404/301/302 才启用本地文件"，于是后端自带 certbot 目录、
	// 有残留同名文件、或回源落到默认站点返回 200 时，本地文件直接作废。
	// 本地文件只有 SamWaf 自己发起过申请时才存在，它天然比后端更权威。
	if content, ok := loadChallengeContent(weblogfrist.HOST_CODE, token); ok {
		resp.StatusCode = http.StatusOK
		resp.Status = http.StatusText(http.StatusOK)
		resp.Body = io.NopCloser(bytes.NewBuffer([]byte(content)))
		resp.ContentLength = int64(len(content))
		resp.Header.Set("Content-Length", strconv.FormatInt(int64(len(content)), 10))
		// 后端可能带着 gzip 之类的编码头，正文被换掉之后必须删掉，
		// 否则 CA 会按 gzip 去解一段明文，报的错还跟证书完全无关
		resp.Header.Del("Content-Encoding")

		weblogfrist.ACTION = "放行"
		weblogfrist.STATUS = resp.Status
		weblogfrist.STATUS_CODE = resp.StatusCode
		weblogfrist.RULE = "ACME证书校验"
		weblogfrist.TASK_FLAG = 1
		weblogfrist.BackendCheckCost = time.Now().UnixNano()/1e6 - backendCheckStart
		global.GQEQUE_LOG_DB.Enqueue(weblogfrist)

		infoACMEChallengeHit(weblogfrist.HOST, weblogfrist.HOST_CODE, weblogfrist.URL, filePath, resp.StatusCode)
		return true
	}

	// 本地没有挑战文件：把后端响应原样交给 CA。
	// 这对"用户自己在后端跑 certbot"是正确行为，对"SamWaf 自己申请"则一定失败，
	// 所以要把两种情况的处置建议都写清楚。
	if resp.StatusCode != 404 && resp.StatusCode != 301 && resp.StatusCode != 302 {
		// 后端在该路径上抢答了一个"看起来正常"的响应。
		//
		// sslhttp_check 的语义已经收窄成"要不要为这种情况写告警"：
		// 本地挑战文件在上面就已经无条件优先了，这个开关不再影响能否签发，
		// 只是留给"后端自己跑 certbot"的用户关掉无谓告警。
		if global.GCONFIG_RECORD_SSLHTTP_CHECK == 1 {
			warnACMEChallenge(weblogfrist.HOST, weblogfrist.HOST_CODE, weblogfrist.URL, token, filePath, resp.StatusCode,
				"本地无挑战文件，且后端对该路径返回了非 404/301/302",
				"若证书是在 SamWaf 里申请的：确认申请是否就在本站点(核对站点编码)；若后端自己跑 certbot：属正常，可在【证书文件验证设置】里关掉本告警")
		}
		return true
	}

	warnACMEChallenge(weblogfrist.HOST, weblogfrist.HOST_CODE, weblogfrist.URL, token, filePath, resp.StatusCode,
		"本地挑战文件不存在或为空，已把后端响应原样返回给 CA",
		"1)核对证书是否就在本站点(站点编码)发起 2)确认该域名80端口流量确实进了SamWaf(在网站日志搜这个token) 3)确认申请时该目录下已生成文件")
	return true
}
