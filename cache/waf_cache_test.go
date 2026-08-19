package cache

import (
	"testing"
	"time"
)

func TestWafCache_SetWithTTl(t *testing.T) {
	wafcache := InitWafCache()
	wafcache.SetWithTTl("KEY1", "我是key1的值", 5*time.Second)
	time.Sleep(65 * time.Second)
	key1Value := wafcache.Get("KEY1")
	if str, ok := key1Value.(string); ok {
		println(str)
	}
	time.Sleep(65 * time.Second)

}
func TestWafCache_GetExpireTime(t *testing.T) {
	wafcache := InitWafCache()
	wafcache.SetWithTTl("KEY1", "我是key1的值", 5*time.Minute)
	key1Value, err := wafcache.GetExpireTime("KEY1")
	if err == nil {
		println(key1Value.String())
	}
}

func TestWafCache_GetExpireTimeForever(t *testing.T) {
	wafcache := InitWafCache()
	wafcache.Set("KEY1", "我是key1的值")
	key1Value, err := wafcache.GetExpireTime("KEY1")
	if err == nil {
		println(key1Value.String())
	}
}
func TestWafCache_GetString(t *testing.T) {
	wafcache := InitWafCache()
	wafcache.SetWithTTl("KEY1", "我是key1的值字符串", 5*time.Second)
	key1Value, err := wafcache.GetString("KEY1")
	if err == nil {
		println(key1Value)
	}
}
func TestWafCache_IsKeyExist(t *testing.T) {
	wafcache := InitWafCache()
	bExist := wafcache.IsKeyExist("KEY1")
	if bExist {
		println("存在")
	} else {
		println("不存在")
	}
}

// TestWafCache_SetWithTTl_KeepsCreateTime 锁定内存后端的既有语义：
// 对已存在的 key，SetWithTTl 沿用原 createTime，到期时刻 = 原 createTime + 新 ttl。
// 这正是"改密后令牌当场失效"那个 bug 的成因，改动此行为前必须先评估所有调用方。
func TestWafCache_SetWithTTl_KeepsCreateTime(t *testing.T) {
	c := InitWafCache()
	c.SetWithTTl("K", "v", 2*time.Second)
	time.Sleep(1200 * time.Millisecond)

	// 已过 1.2s，此时"剩余 0.8s"。按 now+ttl 语义写入 800ms 应还活着；
	// 按内存后端的 createTime 语义则是 createTime+800ms，早已过期。
	c.SetWithTTl("K", "v2", 800*time.Millisecond)
	if c.IsKeyExist("K") {
		t.Fatal("SetWithTTl 对已存在 key 应沿用原 createTime（此处应判定为已过期），语义被改动了")
	}
}

// TestWafCache_SetWithTTlRenewTime_ResetsCreateTime 续命语义：从 now 重新计时。
func TestWafCache_SetWithTTlRenewTime_ResetsCreateTime(t *testing.T) {
	c := InitWafCache()
	c.SetWithTTl("K", "v", 2*time.Second)
	time.Sleep(1200 * time.Millisecond)

	c.SetWithTTlRenewTime("K", "v2", 2*time.Second)
	if !c.IsKeyExist("K") {
		t.Fatal("SetWithTTlRenewTime 应从当前时刻重新计时，key 不该过期")
	}
	time.Sleep(1200 * time.Millisecond)
	if !c.IsKeyExist("K") {
		t.Fatal("续期后总寿命应为 now+2s，1.2s 后仍应存活")
	}
}
