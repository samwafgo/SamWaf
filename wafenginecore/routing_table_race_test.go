package wafenginecore

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
)

// TestRoutingRCURace 并发压测 RCU 路由快照：多读者(rt() + 读 HostSafe 字段) + 字段级 COW 写者(UpdateHost)
// + 结构级写者(增删 host) 同时跑，用 `go test -race -run TestRoutingRCURace` 必须干净、不 panic。
//
// 该用例验证设计文档中“读无锁、写 COW、读不撕裂/不崩溃”的核心不变量。
// 单独运行(-run)以避开本包其它 t.Parallel() 测试在 zlog.InitZLog 上的既有竞态噪声。
func TestRoutingRCURace(t *testing.T) {
	waf := &WafEngine{}
	waf.InitRouting()

	// 预置若干 host（直接构建快照，避免依赖 DB）
	const hostCount = 8
	waf.withWriteTable(func(nt *routingTable) {
		for i := 0; i < hostCount; i++ {
			key := "h" + strconv.Itoa(i) + ":80"
			code := "code" + strconv.Itoa(i)
			hs := &wafenginmodel.HostSafe{
				Host:               model.Hosts{Code: code, GUARD_STATUS: 1},
				LoadBalanceRuntime: &wafenginmodel.LoadBalanceRuntime{},
				RuleData:           []model.Rules{},
				IPBlockLists:       []model.IPBlockList{},
			}
			nt.HostTarget[key] = hs
			nt.HostCode[code] = key
		}
	})

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// 读者：持续读快照与 HostSafe 字段（模拟请求热路径）
	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				rtab := waf.rt()
				for i := 0; i < hostCount; i++ {
					if h, ok := rtab.HostTarget["h"+strconv.Itoa(i)+":80"]; ok && h != nil {
						_ = h.Host.GUARD_STATUS
						_ = len(h.RuleData)
						_ = len(h.IPBlockLists)
					}
				}
			}
		}()
	}

	// 字段级 COW 写者：不断热更新各 host 的名单/规则
	for w := 0; w < 3; w++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			n := seed
			for {
				select {
				case <-stop:
					return
				default:
				}
				code := "code" + strconv.Itoa(n%hostCount)
				waf.UpdateHost(code, func(h *wafenginmodel.HostSafe) {
					h.IPBlockLists = []model.IPBlockList{{Ip: "1.2.3." + strconv.Itoa(n%256)}}
				})
				waf.UpdateHostRules(code, []model.Rules{})
				n++
			}
		}(w * 7)
	}

	// 结构级写者：不断增删一个临时 host（COW 整表替换）
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			key := "tmp:80"
			hs := &wafenginmodel.HostSafe{Host: model.Hosts{Code: "tmpcode"}, LoadBalanceRuntime: &wafenginmodel.LoadBalanceRuntime{}}
			waf.withWriteTable(func(nt *routingTable) {
				nt.HostTarget[key] = hs
				nt.HostCode["tmpcode"] = key
			})
			waf.withWriteTable(func(nt *routingTable) {
				delete(nt.HostTarget, key)
				delete(nt.HostCode, "tmpcode")
			})
		}
	}()

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
}
