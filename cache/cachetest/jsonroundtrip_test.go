package cachetest_test

import (
	"SamWaf/cache"
	"SamWaf/cache/cachetest"
	"testing"
	"time"
)

type demoVal struct {
	Name string    `json:"name"`
	At   time.Time `json:"at"`
}

// 钉死跨后端语义：结构体经缓存往返必须用 GetAs 读取，两种后端结果一致；
// 而 Get 对结构体的返回形态是后端相关的（内存保留原类型，JSON 类后端是 map 泛型），
// 这正是"结构体禁止对 Get 做裸断言"契约的回归依据。
func TestStructRoundTripAcrossBackends(t *testing.T) {
	var _ cache.CacheStore = cachetest.NewJSONRoundTrip() // 编译期确认满足接口

	stores := map[string]cache.CacheStore{
		"内存后端":     cache.InitWafCache(),
		"JSON泛型后端": cachetest.NewJSONRoundTrip(),
	}
	for name, store := range stores {
		t.Run(name, func(t *testing.T) {
			want := demoVal{Name: "n1", At: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)}
			store.SetWithTTl("K", want, time.Minute)

			var got demoVal
			if err := store.GetAs("K", &got); err != nil {
				t.Fatalf("GetAs 应命中，实际 %v", err)
			}
			if got != want {
				t.Fatalf("结构体往返后不一致：got %+v want %+v", got, want)
			}

			var missing demoVal
			if err := store.GetAs("NOT_EXIST", &missing); err == nil {
				t.Fatal("未命中应返回错误")
			}

			if !store.IsKeyExist("K") || store.IsKeyExist("NOT_EXIST") {
				t.Fatal("IsKeyExist 判定不对")
			}
			store.Remove("K")
			if store.IsKeyExist("K") {
				t.Fatal("Remove 后不应再存在")
			}
		})
	}
}

// Get 的后端差异是设计现状，写在这里防止有人误把它当成一致语义：
// 读侧要类型安全一律走 GetAs。
func TestGetReturnsBackendSpecificShape(t *testing.T) {
	want := demoVal{Name: "n1", At: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)}

	jsonStore := cachetest.NewJSONRoundTrip()
	jsonStore.SetWithTTl("K", want, time.Minute)
	got := jsonStore.Get("K")
	m, ok := got.(map[string]interface{})
	if !ok {
		t.Fatalf("JSON 类后端 Get 对结构体应返回 map 泛型，实际 %T", got)
	}
	if m["name"] != "n1" {
		t.Fatalf("泛型 map 内容不对：%v", m)
	}

	memStore := cache.InitWafCache()
	memStore.SetWithTTl("K", want, time.Minute)
	if v, ok := memStore.Get("K").(demoVal); !ok || v != want {
		t.Fatalf("内存后端 Get 应保留原始结构体类型，实际 %T", memStore.Get("K"))
	}
}

func TestScalarRoundTripAcrossBackends(t *testing.T) {
	stores := map[string]cache.CacheStore{
		"内存后端":     cache.InitWafCache(),
		"JSON泛型后端": cachetest.NewJSONRoundTrip(),
	}
	for name, store := range stores {
		t.Run(name, func(t *testing.T) {
			store.SetWithTTl("S", "hello", time.Minute)
			if s, err := store.GetString("S"); err != nil || s != "hello" {
				t.Fatalf("GetString 应取回 hello，实际 %q err=%v", s, err)
			}
			store.SetWithTTl("N", 42, time.Minute)
			if n, err := store.GetInt("N"); err != nil || n != 42 {
				t.Fatalf("GetInt 应取回 42，实际 %d err=%v", n, err)
			}
		})
	}
}
