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
func TestWafCache_GetLastTime(t *testing.T) {
	wafcache := InitWafCache()
	wafcache.SetWithTTl("KEY1", "我是key1的值", 5*time.Second)
	key1Value, err := wafcache.GetLastTime("KEY1")
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
