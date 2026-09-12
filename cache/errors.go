package cache

import "errors"

// 缓存读取失败分两类，调用方必须能区分：
// 键不存在是正常结果，后端不可用是故障。凡是拿缓存做凭证判定的链路
// （管理端令牌、访问会话），把后者当成前者就等于把一次网络抖动判成"凭证失效"。
var (
	// ErrCacheMiss 键不存在（含已过期）
	ErrCacheMiss = errors.New("缓存中不存在该键")
	// ErrCacheBackend 缓存后端本次不可用（超时、连接异常、连接池等待超时等）
	ErrCacheBackend = errors.New("缓存后端不可用")
)

// maskCacheKey 键名可能直接带凭证（如令牌缓存键就是前缀+令牌本体），
// 日志只保留大写前缀与其后 8 个字符。
func maskCacheKey(key string) string {
	// 前缀扫描上限：现有最长前缀 CACHE_TOKEN_BINDFAIL_ 是 21 个字符。
	// 设上限是为了万一某类键的值本身带大写，也不会被整段当成前缀留在日志里。
	const maxPrefix = 24
	i := 0
	for i < len(key) && i < maxPrefix && (key[i] == '_' || (key[i] >= 'A' && key[i] <= 'Z')) {
		i++
	}
	if i >= len(key) {
		return key
	}
	rest := key[i:]
	if len(rest) > 8 {
		return key[:i] + rest[:8] + "..."
	}
	return key[:i] + rest
}
