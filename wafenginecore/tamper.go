package wafenginecore

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/spec"
	"SamWaf/utils"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"gorm.io/gorm"
)

// tamperLearning 防止同一规则并发重复学习（内存态，key=ruleId）
var tamperLearning sync.Map

// tamperDecision 防篡改判定结果
type tamperDecision int

const (
	tamperPass     tamperDecision = iota // 未篡改，放行
	tamperCapture                        // 未学习，需捕获基线
	tamperTampered                       // 已篡改
	tamperSkip                           // 学习失败等，跳过（不保护）
)

// sha256Hex 计算字节内容的 sha256 十六进制串
func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// matchTamperRule 按路径精确匹配启用中的防篡改规则（r.URL.Path 天然不含 query）
func matchTamperRule(rules []model.TamperRule, path string) *model.TamperRule {
	for i := range rules {
		if rules[i].IsEnable == 1 && rules[i].Url == path {
			return &rules[i]
		}
	}
	return nil
}

// isTamperCandidate 是否需要做防篡改比对：GET + 规则启用 + (忽略query 或 无query)
func isTamperCandidate(method, rawQuery string, rule model.TamperRule) bool {
	if !strings.EqualFold(method, http.MethodGet) {
		return false
	}
	if rule.IsEnable != 1 {
		return false
	}
	if rule.IgnoreQuery == 0 && rawQuery != "" {
		return false
	}
	return true
}

// overBaselineCap 基线正文是否超过大小上限
func overBaselineCap(size, maxKB int) bool {
	if maxKB <= 0 {
		maxKB = 1024
	}
	return size > maxKB*1024
}

// evaluateTamper 依据基线状态与实时哈希判定
func evaluateTamper(liveHash string, rule model.TamperRule) tamperDecision {
	switch rule.BaselineStatus {
	case 0:
		return tamperCapture
	case 1:
		if liveHash == rule.BaselineHash {
			return tamperPass
		}
		return tamperTampered
	default:
		return tamperSkip
	}
}

// readDecompressedBody 读取响应正文并按 Content-Encoding 解压，返回解压后字节；
// 同时把 resp.Body 复位为原始字节，供后续常规处理再次读取。
// 以“解压后内容”为哈希基准，避免同一文件因 Accept-Encoding 不同(压/不压)导致哈希不一致。
func readDecompressedBody(resp *http.Response) ([]byte, error) {
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// 复位原始 body 供下游再次读取
	resp.Body = io.NopCloser(bytes.NewReader(raw))

	switch strings.ToLower(resp.Header.Get("Content-Encoding")) {
	case "gzip":
		zr, e := gzip.NewReader(bytes.NewReader(raw))
		if e != nil {
			return nil, e
		}
		defer zr.Close()
		return io.ReadAll(zr)
	case "deflate":
		fr := flate.NewReader(bytes.NewReader(raw))
		defer fr.Close()
		return io.ReadAll(fr)
	case "br":
		return io.ReadAll(brotli.NewReader(bytes.NewReader(raw)))
	case "zstd":
		zr, e := zstd.NewReader(bytes.NewReader(raw))
		if e != nil {
			return nil, e
		}
		defer zr.Close()
		return io.ReadAll(zr)
	default:
		return raw, nil
	}
}

// checkAndHandleTamper 网页防篡改主流程。返回 true 表示已完整处理（回吐基线并记日志），
// 调用方应直接 return nil；返回 false 则继续正常应答处理。
func (waf *WafEngine) checkAndHandleTamper(resp *http.Response, r *http.Request, host string, weblog *innerbean.WebLog) bool {
	hostTarget, ok := waf.rt().HostTarget[host]
	if !ok {
		return false
	}
	cfg := model.ParseTamperConfig(hostTarget.Host.TamperJSON)
	if cfg.IsEnable != 1 {
		return false
	}
	if !strings.EqualFold(r.Method, http.MethodGet) {
		return false
	}
	// 仅对正常 200 响应学习/比对，避免把 404/500/302 学成基线
	if resp.StatusCode != http.StatusOK {
		return false
	}
	rule := matchTamperRule(hostTarget.TamperRules, r.URL.Path)
	if rule == nil {
		return false
	}
	if rule.IgnoreQuery == 0 && r.URL.RawQuery != "" {
		return false
	}

	body, err := readDecompressedBody(resp)
	if err != nil || len(body) == 0 {
		return false
	}

	switch evaluateTamper(sha256Hex(body), *rule) {
	case tamperCapture:
		waf.captureTamperBaseline(rule, body, resp.Header.Get("Content-Type"), resp.StatusCode, cfg)
		return false
	case tamperPass, tamperSkip:
		return false
	case tamperTampered:
		// 命中篡改：alert 仅告警不替换；replace 回吐正确副本并短路
		replaced := cfg.Action != "alert"
		// 统计 + 告警（异步，文案区分是否已替换）
		waf.onTamperDetected(rule, weblog, replaced)
		weblog.RULE = "网页防篡改"
		weblog.RISK_LEVEL = 3
		weblog.GUEST_IDENTIFICATION = "网页篡改"
		if !replaced {
			// 仅告警：不替换，放行后端页，日志由正常流程记录
			return false
		}
		// replace：回吐基线正确副本并短路
		waf.serveTamperBaseline(resp, rule)
		// 与 WAF 其它拦截一致的处置态（访问日志「状态」列识别 放行/阻止/禁止）
		weblog.ACTION = "阻止"
		weblog.STATUS = resp.Status
		weblog.STATUS_CODE = resp.StatusCode
		weblog.RES_CONTENT_LENGTH = sanitizeContentLength(resp.ContentLength)
		weblog.ResHeader = joinHeader(resp.Header)
		waf.enqueueTamperLog(weblog, hostTarget.Host.EXCLUDE_URL_LOG)
		return true
	}
	return false
}

// serveTamperBaseline 用基线正文替换响应体（基线为解压后原文，未压缩直出）
func (waf *WafEngine) serveTamperBaseline(resp *http.Response, rule *model.TamperRule) {
	content := rule.BaselineContent
	resp.Body = io.NopCloser(bytes.NewReader(content))
	resp.Header.Del("Content-Encoding")
	if rule.ContentType != "" {
		resp.Header.Set("Content-Type", rule.ContentType)
	}
	resp.ContentLength = int64(len(content))
	resp.Header.Set("Content-Length", strconv.Itoa(len(content)))
	resp.StatusCode = http.StatusOK
	resp.Status = "200 OK"
}

// captureTamperBaseline 被动捕获基线（异步、按规则去重），完成后触发热重载
func (waf *WafEngine) captureTamperBaseline(rule *model.TamperRule, body []byte, contentType string, statusCode int, cfg model.TamperConfig) {
	if _, loaded := tamperLearning.LoadOrStore(rule.Id, struct{}{}); loaded {
		return
	}
	ruleId := rule.Id
	hostCode := rule.HostCode
	contentCopy := make([]byte, len(body))
	copy(contentCopy, body)

	go func() {
		defer tamperLearning.Delete(ruleId)
		now := time.Now().Format("2006-01-02 15:04:05")
		upd := map[string]interface{}{
			"LastLearnTime": now,
			"ContentSize":   len(contentCopy),
		}
		if overBaselineCap(len(contentCopy), cfg.MaxSizeKB) {
			upd["BaselineStatus"] = 2
			upd["BaselineMsg"] = fmt.Sprintf("正文 %d 字节超过上限 %d KB，未学习", len(contentCopy), cfg.MaxSizeKB)
		} else {
			upd["BaselineHash"] = sha256Hex(contentCopy)
			upd["BaselineContent"] = contentCopy
			upd["ContentType"] = contentType
			upd["StatusCode"] = statusCode
			upd["BaselineStatus"] = 1
			upd["BaselineMsg"] = ""
		}
		global.GWAF_LOCAL_DB.Model(&model.TamperRule{}).Where("id=?", ruleId).Updates(upd)
		waf.notifyTamperReload(hostCode)
	}()
}

// onTamperDetected 命中篡改后异步累计次数并发告警；replaced 区分是否已回吐正确副本
func (waf *WafEngine) onTamperDetected(rule *model.TamperRule, weblog *innerbean.WebLog, replaced bool) {
	ruleId := rule.Id
	domain := weblog.HOST
	srcIp := weblog.SRC_IP
	url := weblog.URL
	go func() {
		now := time.Now().Format("2006-01-02 15:04:05")
		global.GWAF_LOCAL_DB.Model(&model.TamperRule{}).Where("id=?", ruleId).Updates(map[string]interface{}{
			"TamperCount":    gorm.Expr("tamper_count + 1"),
			"LastTamperTime": now,
		})
		ruleInfo := "检测到网页被篡改（仅告警，未替换）：" + url
		if replaced {
			ruleInfo = "检测到网页被篡改，已回吐正确副本：" + url
		}
		global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.RuleMessageInfo{
			BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "网页防篡改", Server: global.GWAF_CUSTOM_SERVER_NAME},
			Domain:          domain,
			RuleInfo:        ruleInfo,
			Ip:              fmt.Sprintf("%s (%s)", srcIp, utils.GetCountry(srcIp)),
		})
	}()
}

// notifyTamperReload 重新读取该站点防篡改规则并推送到引擎热更新
func (waf *WafEngine) notifyTamperReload(hostCode string) {
	var list []model.TamperRule
	global.GWAF_LOCAL_DB.Where("host_code=?", hostCode).Find(&list)
	global.GWAF_CHAN_MSG <- spec.ChanCommonHost{
		HostCode: hostCode,
		Type:     enums.ChanTypeTamperRule,
		Content:  list,
	}
}

// enqueueTamperLog 防篡改替换短路时记录访问日志（复用 all/abnormal + EXCLUDE_URL_LOG 规则）。
// 反代/静态两条链路共用：调用方先填好 STATUS/STATUS_CODE/RES_CONTENT_LENGTH/ResHeader/ACTION，再传各自的 EXCLUDE_URL_LOG。
func (waf *WafEngine) enqueueTamperLog(weblog *innerbean.WebLog, excludeURLLog string) {
	datetimeNow := time.Now()
	weblog.TimeSpent = datetimeNow.UnixNano()/1e6 - weblog.UNIX_ADD_TIME
	weblog.TASK_FLAG = 1

	// 防篡改替换属于异常事件，all / abnormal 两种模式都记录
	if excludeURLLog != "" {
		for _, line := range strings.Split(excludeURLLog, "\n") {
			if line != "" && strings.HasPrefix(weblog.URL, line) {
				return
			}
		}
	}
	global.GQEQUE_LOG_DB.Enqueue(weblog)
}
