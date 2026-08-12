package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/utils"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ACME(HTTP-01) 证书校验的诊断日志。
//
// 为什么要单独有这么一组函数：签发失败时，用户手里只有 CA 回的一句
// "Invalid response from http://xxx/.well-known/acme-challenge/<token>: 404"，
// 看不出到底卡在哪一层。实际至少有三种完全不同的原因：
//   - 本地校验文件压根没生成（申请侧的问题）
//   - 生成了，但请求匹配到的是另一条站点记录，读的目录和写的目录对不上
//   - 都对，但后端对该路径返回了非 404/301/302，本地校验文件没被采用（sslhttp_check）
//

// acmeWarnInterval 同一站点两条诊断日志之间的最小间隔（秒）。
// warnAccessNoCenter 保持一致（atomic + CAS，不引锁）。
const acmeWarnInterval int64 = 300

// acmeWarnAt 记录每个站点上一次打印诊断日志的时间戳（秒）。
//
// key 用 host_code 而不是请求里的 Host：Host 由客户端控制，在兜底站点(GLOBAL_HOST)下
// 攻击者换个 Host 就能把这个 map 撑大；host_code 的取值范围是已配置的站点数，有界。
var acmeWarnAt sync.Map // host_code -> *atomic.Int64

// acmeChallengeFilePath 返回挑战文件应该在的绝对路径。
//
// 拼法必须与申请时传给 lego 的 savePath 一致（见 sslorder.go 的
// GetCurrentDir()/data/vhost/<HostCode>），否则就是"写在一处、读在另一处"。
// 统一成一个函数，避免调用点各拼各的。
func acmeChallengeFilePath(hostCode, token string) string {
	return utils.GetCurrentDir() + "/data/vhost/" + hostCode + "/.well-known/acme-challenge/" + token
}

// acmeTokenFromURL 从 /.well-known/acme-challenge/<token> 中取出 token；
// 取不到或不合法返回空串。
//
// 只服务于诊断日志，不参与任何放行判定 —— 放行判定仍在各调用点原有的校验里，
// 这里放宽或收紧都不会影响安全边界。
func acmeTokenFromURL(url string) string {
	urls := strings.Split(url, "/")
	if len(urls) != 4 {
		return ""
	}
	if !utils.IsValidChallengeFile(urls[3]) {
		return ""
	}
	return urls[3]
}

// acmeDiagAllowed 判断当前站点是否允许再打一条诊断日志。
func acmeDiagAllowed(hostCode string) bool {
	v, _ := acmeWarnAt.LoadOrStore(hostCode, new(atomic.Int64))
	last := v.(*atomic.Int64)
	now := time.Now().Unix()
	prev := last.Load()
	return now-prev >= acmeWarnInterval && last.CompareAndSwap(prev, now)
}

// warnACMEChallenge 打印一条 ACME 校验诊断日志（按站点节流）。
//
// backendStatus 传 0 表示这次没有后端响应（请求侧直接处理的场景）。
// token / filePath 允许为空串，表示这次没能解析出来。
func warnACMEChallenge(host, hostCode, url, token, filePath string, backendStatus int, reason, advice string) {
	// 节流判定放在最前面：后面的 os.Stat 是一次系统调用，
	// 必须挡在闸门之后，否则刷这个路径就等于刷磁盘。
	if !acmeDiagAllowed(hostCode) {
		return
	}

	fileState := "未解析出token，无法判断"
	if filePath != "" {
		if _, err := os.Stat(filePath); err == nil {
			fileState = "存在"
		} else if os.IsNotExist(err) {
			fileState = "不存在"
		} else {
			fileState = "无法访问(" + err.Error() + ")"
		}
	}

	backendState := "无后端响应"
	if backendStatus > 0 {
		backendState = strconv.Itoa(backendStatus)
	}

	zlog.Warn(fmt.Sprintf(
		"ACME证书校验诊断：域名=%s 站点编码=%s 请求=%s token=%s 后端状态码=%s 本地校验文件=%s 本地文件=%s 原因=%s 处置建议=%s"+
			"（同一站点该日志%d秒内只打印一条）",
		host, hostCode, url, emptyAsDash(token), backendState, emptyAsDash(filePath), fileState, reason, advice, acmeWarnInterval))
}

// infoACMEChallengeHit 本地校验文件被成功采用时打一条 Info。
// 签发/续期期间才会出现，量极小，不需要节流；有这条日志才能把"成功"和"没走到"区分开。
func infoACMEChallengeHit(host, hostCode, url, filePath string, backendStatus int) {
	backendState := "无后端响应"
	if backendStatus > 0 {
		backendState = strconv.Itoa(backendStatus)
	}
	zlog.Info(fmt.Sprintf("ACME证书校验：已用本地校验文件应答 域名=%s 站点编码=%s 请求=%s 本地校验文件=%s 后端状态码=%s",
		host, hostCode, url, filePath, backendState))
}

func emptyAsDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
