package wafcaptcha

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"SamWaf/enums"
)

// 验证码接口按 IP 限频。
//
// 这些接口此前没有任何频控，可以被无限刷：
//   - 取题类（click_basic / challenge）：每次都要在服务端绘制图片或生成并存储挑战，
//     不设限就是一条"零成本放大服务端开销"的通道；
//   - 交卷类（verify / redeem / validate）：坐标可以暴力试、PoW 答案可以批量兑换，
//     不设限时单 IP 就能把尝试速率推到每秒上千次。
//
// 实现为「动作 + 客户端IP + 固定时间窗」计数：窗口按 Unix 时间分桶，桶键到期自然清零，
// 不依赖缓存 TTL 的续期语义；读-改-写用互斥锁保护（缓存层没有原子自增，
// 与登录失败计数同因——并发下裸 Get→+1→Set 会把计数压平）。
// Redis 后端下多实例之间计数不共享、内存后端下多进程不共享，属已知精度损失：
// 限频在这里是"把刷量从无上限压到每分钟几十次"的减速带，不是精确配额。
const (
	captchaRateWindow = time.Minute

	// captchaRateIssueLimit 取题类接口的每 IP 每分钟上限。正常一屏只取一两次，
	// 公司 NAT 出口也能容纳；限的目标是自动化刷量而不是真人。
	captchaRateIssueLimit = 60
	// captchaRateCheckLimit 交卷类接口的每 IP 每分钟上限。
	captchaRateCheckLimit = 30
)

// 限频动作标识。会作为缓存键的一部分，改名等于让既有计数从头开始。
const (
	rateActionClickBasic = "click_basic"
	rateActionVerify     = "verify"
	rateActionChallenge  = "challenge"
	rateActionRedeem     = "redeem"
	rateActionValidate   = "validate"
)

// captchaRateMu 保护计数的「读-改-写」序列。
var captchaRateMu sync.Mutex

// allowCaptchaRequest 记一次请求并判断是否放行；false 表示超出限额。
func (s *CaptchaService) allowCaptchaRequest(action, clientIP string, limit int) bool {
	if s == nil || s.cache == nil || clientIP == "" {
		// 服务未初始化或拿不到客户端 IP 时不阻断：限频的键就是 IP，没有键可算。
		return true
	}

	bucket := time.Now().Unix() / int64(captchaRateWindow/time.Second)
	key := fmt.Sprintf("%s%s:%s:%d", enums.CACHE_CAPTCHA_RATE, action, clientIP, bucket)

	captchaRateMu.Lock()
	defer captchaRateMu.Unlock()

	cnt, err := s.cache.GetInt(key)
	if err != nil {
		cnt = 0
	}
	if cnt >= limit {
		return false
	}
	s.cache.SetWithTTl(key, cnt+1, captchaRateWindow*2)
	return true
}

// requestLimiterIP 限频专用取 IP：优先用与业务一致的 IPMode 口径，取不到时退回 TCP 对端。
func requestLimiterIP(r *http.Request, byMode string) string {
	if byMode != "" {
		return byMode
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// writeCaptchaRateLimited 超限响应：429 + Retry-After。
//
// 响应体同时带上 code 与 success 两个字段：传统页按 code 判断、capJs 页按 success 判断。
// 两端对 429 的表现都是"可恢复的失败提示"（传统页提示获取/校验失败，widget 进入错误态），
// 不会形成自动重试风暴。
func writeCaptchaRateLimited(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Retry-After", fmt.Sprintf("%d", int(captchaRateWindow/time.Second)))
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write([]byte(`{"code":1,"success":false,"message":"too many requests"}`))
}
