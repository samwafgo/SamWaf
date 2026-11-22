package wafipban

import (
	"SamWaf/cache"
	"encoding/json"
	"time"
)

// readRecordE 将未命中与后端/反序列化故障分开，安全规则不能把查询失败解释成零次失败。
func readRecordE[T any](store cache.CacheStore, key string) (*T, error) {
	if _, memory := store.(*cache.WafCache); memory {
		return loadRecord[T](store, key), nil
	}
	var record *T
	if err := store.GetAs(key, &record); err != nil {
		if cache.IsMiss(err) {
			return nil, nil
		}
		return nil, err
	}
	return record, nil
}

// updateRecord 在 PostgreSQL 事务内调用修改函数；兼容内存路径由原管理器的锁保护。
func updateRecord[T any](store cache.CacheStore, key string, ttl time.Duration, change func(*T) *T) error {
	if updater, ok := store.(cache.JSONUpdater); ok {
		return updater.UpdateJSONE(key, ttl, func(previous []byte) ([]byte, error) {
			var record *T
			if len(previous) > 0 {
				if err := json.Unmarshal(previous, &record); err != nil {
					return nil, err
				}
			}
			return json.Marshal(change(record))
		})
	}
	record, err := readRecordE[T](store, key)
	if err != nil {
		return err
	}
	store.SetWithTTlRenewTime(key, change(record), ttl)
	return nil
}

// loadRecord 从缓存读取结构体记录，两种缓存后端语义一致：
// 内存后端(WafCache) Get 原样返回存入的 Go 值，断言快路径一次命中；
// JSON 类后端(RedisCache) Get 返回 map[string]interface{} 泛型——断言必然失败
// 且白浪费一次往返，直接走 GetAs 反序列化。
//
// 返回的是缓存中的共享快照，调用方不得原地修改：写路径必须先克隆副本、
// 改完再整体回写，读路径才能在无锁状态下安全遍历。
func loadRecord[T any](store cache.CacheStore, key string) *T {
	if _, isMem := store.(*cache.WafCache); isMem {
		val := store.Get(key)
		if val == nil {
			return nil
		}
		// 类型不符说明私有 keyspace 被写入了非预期形态，按不存在处理
		rec, _ := val.(*T)
		return rec
	}
	var rec *T
	if err := store.GetAs(key, &rec); err != nil || rec == nil {
		return nil
	}
	return rec
}

// IsBannedRecord 失败记录是否带封禁阈值戳（自定义规则真实命中过）。
// 封禁列表与归属地查询共用这一判据，避免两处谓词写法漂移。
func IsBannedRecord(r *IPFailureRecord) bool {
	return r != nil && r.TriggerMinutes > 0 && r.TriggerCount > 0
}
