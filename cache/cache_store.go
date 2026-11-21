package cache

import "time"

// CacheStore 是控制台/业务状态的缓存接口，运行后端使用 PostgreSQL KV/TTL。
// 内存、Redis 适配器保留兼容用途；站点响应正文由独立 L1/L2 管理，不放入此接口。
type CacheStore interface {
	Set(key string, value interface{})
	SetWithTTl(key string, value interface{}, ttl time.Duration)
	SetWithTTlRenewTime(key string, value interface{}, ttl time.Duration)
	// Get 返回缓存里的原始值。注意后端差异：内存后端返回存入的 Go 值（类型保留），
	// JSON 类后端(RedisCache)返回解码到 interface{} 的泛型（对象是 map[string]interface{}，
	// 数组是 []interface{}）——结构体一律用 GetAs 读取，不要对 Get 的返回值做结构体断言。
	Get(key string) interface{}
	// GetAs 将缓存值反序列化到 out（out 必须为指针）。
	// 对于 Redis 等非内存后端，Get() 返回的是 map[string]interface{}，
	// 无法直接类型断言为具体 struct；应使用 GetAs 代替。
	//
	// 返回值区分两种失败：ErrCacheMiss（键不存在）与 ErrCacheBackend（后端不可用），
	// 用 errors.Is 判定。其余错误来自反序列化。
	GetAs(key string, out interface{}) error
	// GetAsEx 读取并同时续期，一次往返完成。ttl<=0 时等价于 GetAs。
	// 每请求都要读一次的凭证类缓存用它，可省掉单独的查剩余时间与续期两次往返。
	GetAsEx(key string, out interface{}, ttl time.Duration) error
	// Touch 只续期不读取值。键不存在返回 ErrCacheMiss。
	Touch(key string, ttl time.Duration) error
	GetBytes(key string) ([]byte, error)
	GetString(key string) (string, error)
	GetInt(key string) (int, error)
	// IsKeyExist 后端错误一律按 false 返回。
	// 需要区分"确实不存在"与"这次没读到"的场景（尤其是安全判定）用 ExistsE。
	IsKeyExist(key string) bool
	// ExistsE 与 IsKeyExist 相同，但把后端错误单独返回。
	ExistsE(key string) (bool, error)
	Remove(key string) interface{}
	GetExpireTime(key string) (time.Time, error)
	ListAvailableKeys() map[string]time.Duration
	ListAvailableKeysWithPrefix(prefix string) map[string]time.Duration
}

// AtomicAdder 提供可选的「不存在才写入」原子能力，避免为兼容旧适配器而扩展必选接口。
// PostgreSQL 用条件 UPSERT 保证同键并发只有一个成功；错误不能解释为成功占用。
type AtomicAdder interface {
	// AddWithTTL 返回是否成功首次写入，未到期的同键不能被覆盖，过期键允许重新占用。
	AddWithTTL(key string, value interface{}, ttl time.Duration) (bool, error)
}

// BackendStats 缓存后端运行状况，供运行诊断读取
type BackendStats struct {
	Backend   string    `json:"backend"`
	ErrCount  uint64    `json:"err_count"`
	LastErrAt time.Time `json:"last_err_at"`
	LastErr   string    `json:"last_err"`
}

// BackendStater 可选能力：后端实现了才有错误统计（内存后端不会失败，无需实现）
type BackendStater interface {
	BackendStats() BackendStats
}

// BackendDescriber 可选能力：用于启动日志打印当前缓存后端形态（不含口令）
type BackendDescriber interface {
	Describe() string
}
