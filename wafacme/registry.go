// Package wafacme 维护 HTTP-01 挑战的运行期状态：token 注册表、门闩、读盘限速。
//
// 为什么要单独一个包：
// 写入方是证书申请侧（utils/ssl 里的 lego provider），读取方是流量侧（wafenginecore），
// 而 wafenginecore 已经 import 了 utils/ssl —— 状态放在任何一侧都会形成循环依赖，
// 只能沉到一个两边都能 import 的底层包里。
//
// 这里所有导出函数都必须是并发安全且极廉价的：流量侧会在每个
// /.well-known/acme-challenge/ 请求上调用它们，而这个路径是互联网上被扫烂的路径，
// 任何人都可以随意构造请求打进来。
package wafacme

import (
	"SamWaf/utils"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// gateWindow Present 之后门闩保持开启的时长。
	// 一次 HTTP-01 校验通常几秒内结束，留足冗余即可，开太久等于把防刷闸门长期敞开。
	gateWindow = 10 * time.Minute

	// gateTail CleanUp 之后门闩仍然保留的时间。
	// CA 偶尔会重试校验，清理完立刻关闸会让重试落空。
	gateTail = 60 * time.Second

	// sentinelCacheTTL 哨兵文件的缓存时长。
	// 没有这个缓存，被刷时每个请求都会变成一次 stat；有了它最多每 5 秒一次。
	sentinelCacheTTL = 5 * time.Second

	// maxDiskReadsPerSec 内存表未命中时，每秒允许的读盘次数上限（全进程）。
	// 这条路径只在蓝绿升级、双 Worker 并存时才会走到，正常情况下一次都不会触发，
	// 所以给一个很小的额度就够，主要作用是防止"签发窗口内正好被刷"。
	maxDiskReadsPerSec = 20

	// maxChallengeFileSize 挑战文件读取上限。
	// 真实的 keyAuth 只有 87 字节左右，1KB 足够，避免有人往那个目录塞大文件。
	maxChallengeFileSize = 1024

	// sentinelName 跨进程哨兵文件名，落在 data 目录下。
	sentinelName = "acme_active"
)

var (
	// activeUntil L1 进程内门闩（unix 秒）。证书申请跑在 Worker 进程，
	// 与流量处理同进程，所以绝大多数情况这一层就够了。
	activeUntil atomic.Int64

	// tokens 挑战注册表：hostCode+token -> keyAuth。
	// 命中它就不需要读盘，是防刷的主力。
	tokens sync.Map // string -> *entry

	// 哨兵文件的检查结果缓存
	sentinelCheckedAt atomic.Int64
	sentinelUntil     atomic.Int64

	// 读盘限速的一秒窗口
	diskWindow atomic.Int64
	diskCount  atomic.Int64

	// dataDir 哨兵文件所在的 data 目录；未注入时由 currentDataDir 按程序目录推导
	dataDir atomic.Value // string
)

type entry struct {
	keyAuth   string
	expiresAt int64
}

// SetDataDir 注入 data 目录（形如 <程序目录>/data）。
// 由启动流程或申请侧调用一次即可；没设置时哨兵功能自动降级为不可用（只用 L1 门闩）。
func SetDataDir(dir string) {
	dataDir.Store(dir)
}

// currentDataDir 取 data 目录；没被显式注入时按程序目录推导。
//
// 这个兜底是必需的：跨进程哨兵存在的意义就是让**没有发起过申请的那个 Worker**
// 也能知道"当前有挑战正在进行"。而 SetDataDir 只在申请侧构造 provider 时才会被调用，
// 那个 Worker 永远不会调用它——只靠注入的话，L2 门闩在最需要它的场景里恰好是失效的。
func currentDataDir() string {
	if v, ok := dataDir.Load().(string); ok && v != "" {
		return v
	}
	dir := filepath.Join(utils.GetCurrentDir(), "data")
	dataDir.Store(dir)
	return dir
}

func key(hostCode, token string) string {
	return hostCode + "\x00" + token
}

// Present 登记一个挑战 token，同时开启门闩并写哨兵文件。
// 由 lego provider 的 Present 调用。
func Present(hostCode, token, keyAuth string) {
	now := time.Now()
	expires := now.Add(gateWindow).Unix()

	tokens.Store(key(hostCode, token), &entry{keyAuth: keyAuth, expiresAt: expires})
	openGate(expires)
	sweepExpired(now.Unix())
}

// CleanUp 注销一个挑战 token。门闩不立即关闭，保留 gateTail 以容忍 CA 重试。
func CleanUp(hostCode, token string) {
	tokens.Delete(key(hostCode, token))

	tail := time.Now().Add(gateTail).Unix()
	// 只把门闩往回收，不往后延：CleanUp 不该延长闸门开启时间
	for {
		cur := activeUntil.Load()
		if cur <= tail || activeUntil.CompareAndSwap(cur, tail) {
			break
		}
	}
	writeSentinel(activeUntil.Load())
}

func openGate(until int64) {
	for {
		cur := activeUntil.Load()
		if cur >= until || activeUntil.CompareAndSwap(cur, until) {
			break
		}
	}
	writeSentinel(until)
}

// GateOpen 判断当前是否存在进行中的挑战。
//
// 这是防刷的第一道闸门，必须排在任何磁盘操作之前：没有进行中的挑战时，
// 无论怎么刷 /.well-known/acme-challenge/ 都只花掉一次 atomic.Load。
func GateOpen() bool {
	now := time.Now().Unix()
	if now <= activeUntil.Load() {
		return true
	}
	return sentinelOpen(now)
}

// sentinelOpen 跨进程门闩（L2）。
//
// 优雅升级期间 REUSEPORT 会让新旧两个 Worker 同时收流量：申请跑在 Worker A，
// CA 的校验请求却可能落到 Worker B —— B 的内存注册表是空的、L1 门闩也是关的。
// 哨兵文件是两个进程唯一共享的事实来源。
//
// 带 5 秒缓存，所以被刷时不会退化成每请求一次 stat。
func sentinelOpen(now int64) bool {
	last := sentinelCheckedAt.Load()
	if now-last >= int64(sentinelCacheTTL/time.Second) {
		// CAS 保证并发时只有一个 goroutine 真去读文件
		if sentinelCheckedAt.CompareAndSwap(last, now) {
			sentinelUntil.Store(readSentinel())
		}
	}
	return now <= sentinelUntil.Load()
}

func sentinelPath() string {
	dir := currentDataDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, sentinelName)
}

func readSentinel() int64 {
	path := sentinelPath()
	if path == "" {
		return 0
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func writeSentinel(until int64) {
	path := sentinelPath()
	if path == "" {
		return
	}
	// 写失败不影响签发（L1 门闩仍然有效），只是升级窗口内的跨进程兜底失效，所以忽略错误
	_ = os.WriteFile(path, []byte(strconv.FormatInt(until, 10)), 0o600)
}

// Lookup 查内存注册表。命中即可直接应答，不需要碰磁盘。
func Lookup(hostCode, token string) (string, bool) {
	v, ok := tokens.Load(key(hostCode, token))
	if !ok {
		return "", false
	}
	e := v.(*entry)
	if time.Now().Unix() > e.expiresAt {
		tokens.Delete(key(hostCode, token))
		return "", false
	}
	return e.keyAuth, true
}

// AllowDiskRead 内存表未命中时的读盘限速。
//
// 走到这里只有一种正常情形：蓝绿升级期间请求落到了没有登记过该 token 的另一个 Worker。
// 其余都是恶意构造，所以额度给得很小。
func AllowDiskRead() bool {
	now := time.Now().Unix()
	if diskWindow.Load() != now {
		diskWindow.Store(now)
		diskCount.Store(0)
	}
	return diskCount.Add(1) <= maxDiskReadsPerSec
}

// MaxChallengeFileSize 挑战文件读取上限，供流量侧使用。
func MaxChallengeFileSize() int64 {
	return maxChallengeFileSize
}

// ResetForTest 清空注册表并立即关闭门闩，仅供测试使用。
//
// 需要它是因为门闩在 CleanUp 之后还会保留 gateTail（容忍 CA 重试），
// 测试里没法等这段时间，而"门闩关闭时不做任何磁盘 IO"这条断言又必须在关闭状态下才成立。
func ResetForTest() {
	activeUntil.Store(0)
	sentinelUntil.Store(0)
	sentinelCheckedAt.Store(time.Now().Unix())
	tokens.Range(func(k, _ any) bool {
		tokens.Delete(k)
		return true
	})
}

// sweepExpired 顺手清理过期条目。
// 条目数量等于并发签发的挑战数（个位数），正常由 CleanUp 删除；
// 这里兜住 CleanUp 没跑到的情况（比如进程被杀），避免注册表长期残留。
func sweepExpired(now int64) {
	tokens.Range(func(k, v any) bool {
		if e, ok := v.(*entry); ok && now > e.expiresAt {
			tokens.Delete(k)
		}
		return true
	})
}
