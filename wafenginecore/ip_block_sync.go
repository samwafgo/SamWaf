package wafenginecore

import (
	"context"
	"database/sql"
	"sync"
	"time"

	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafdb"
	"SamWaf/wafenginecore/ipset"
	"gorm.io/gorm"
)

// ReloadIPBlocks 从同一只读快照读取版本和全部启用名单，读取失败时完全保留现有路由。
// 一次发布全部站点，确保规则从 A 移到 B 时不存在只刷一边的中间状态。
func (waf *WafEngine) ReloadIPBlocks(ctx context.Context, db *gorm.DB) error {
	waf.ipBlockReloadMu.Lock()
	defer waf.ipBlockReloadMu.Unlock()
	var revision int64
	var rows []model.IPBlockList
	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Raw("SELECT revision FROM samwaf_control.revisions WHERE name='ip_block'").Row().Scan(&revision); err != nil {
			return err
		}
		return tx.Where("is_enable=1").Find(&rows).Error
	}, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return err
	}
	lists := map[string][]model.IPBlockList{}
	for _, row := range rows {
		lists[row.HostCode] = append(lists[row.HostCode], row)
	}
	indexes := map[string]*ipset.MatchSet{}
	groups := map[string][]string{}
	for code, list := range lists {
		indexes[code] = BuildIPBlockIndex(list)
		groups[code] = ExtractBlockGroupCodes(list)
	}
	waf.withWriteTable(func(next *routingTable) {
		copies := map[*wafenginmodel.HostSafe]*wafenginmodel.HostSafe{}
		for key, host := range next.HostTarget {
			if host == nil {
				continue
			}
			copyHost := copies[host]
			if copyHost == nil {
				h := *host
				code := host.Host.Code
				h.IPBlockLists = lists[code]
				h.IPBlockIndex = indexes[code]
				h.IPBlockGroupCodes = groups[code]
				copyHost = &h
				copies[host] = copyHost
			}
			next.HostTarget[key] = copyHost
		}
	})
	waf.ipBlockRevision.Store(revision)
	return nil
}

// StartIPBlockSync 启动前同步确认名单；每秒只读一个版本号，变更/故障恢复后再重载。
// 这条恢复路径不依赖某个 Worker 收到 API 的本地通道消息，也不会逐请求查名单表。
func (waf *WafEngine) StartIPBlockSync(db *gorm.DB) error {
	if db.Dialector.Name() != "postgres" {
		return nil
	}
	if err := wafdb.InstallIPBlockRevision(db); err != nil {
		return err
	}
	waf.ipBlockSyncMu.Lock()
	defer waf.ipBlockSyncMu.Unlock()
	if waf.ipBlockSyncCancel != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	budget, done := context.WithTimeout(ctx, 5*time.Second)
	err := waf.ReloadIPBlocks(budget, db)
	done()
	if err != nil {
		cancel()
		return err
	}
	waf.ipBlockSyncCancel = cancel
	waf.ipBlockSyncDone = make(chan struct{})
	doneChannel := waf.ipBlockSyncDone
	var workers sync.WaitGroup
	workers.Add(1)
	if waf.SystemBanReconciler != nil {
		workers.Add(1)
		go func() {
			defer workers.Done()
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			ticks := 0
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					ticks++
					budget, done := context.WithTimeout(ctx, 45*time.Second)
					_ = waf.SystemBanReconciler(budget, ticks%30 == 0)
					done()
				}
			}
		}()
	}
	go func() {
		defer workers.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				budget, done := context.WithTimeout(ctx, 5*time.Second)
				var revision int64
				err := db.WithContext(budget).Raw("SELECT revision FROM samwaf_control.revisions WHERE name='ip_block'").Row().Scan(&revision)
				if err == nil && revision != waf.ipBlockRevision.Load() {
					_ = waf.ReloadIPBlocks(budget, db)
				}
				done()
			}
		}
	}()
	go func() { workers.Wait(); close(doneChannel) }()
	return nil
}

// StopIPBlockSync 在关闭数据库前停止版本检查，避免悬挂的重载协程访问已关闭连接池。
func (waf *WafEngine) StopIPBlockSync() {
	waf.ipBlockSyncMu.Lock()
	cancel, done := waf.ipBlockSyncCancel, waf.ipBlockSyncDone
	waf.ipBlockSyncCancel = nil
	waf.ipBlockSyncMu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}
