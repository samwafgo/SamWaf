package waf_service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"

	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/utils"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// kernelReconcileNeeded 记录控制操作的不确定结果，数据库和内核不是同一个事务资源。
// 失败立即尝试核对，后台再次恢复；源账本和错误都保留，不能报告已成功下发。
var kernelReconcileNeeded atomic.Bool

// lockKernelLedger 与后台核对使用同一把数据库事务锁，防止重放尚未提交的旧快照。
func lockKernelLedger(tx *gorm.DB) error {
	if tx.Dialector.Name() != "postgres" {
		return nil
	}
	return tx.Exec("SELECT pg_advisory_xact_lock(7357140146)").Error
}

// kernelSnapshot 只恢复本应用手工来源，其他订阅和主机防护来源由各自账本管理。
func (receiver *WafFirewallIPBlockService) kernelSnapshot(tx *gorm.DB) error {
	var rows []model.FirewallIPBlock
	if err := tx.Where("status=? AND (expire_time=0 OR expire_time>?)", "active", time.Now().Unix()).Find(&rows).Error; err != nil {
		return err
	}
	dir := os.Getenv("SAMWAF_BPF_STATE_DIR")
	if dir == "" {
		dir = filepath.Join(utils.GetCurrentDir(), "data", "ebpf")
	}
	_, stateErr := os.Stat(filepath.Join(dir, "state.json"))
	_, pendingErr := os.Stat(filepath.Join(dir, "pending.json"))
	if len(rows) == 0 && os.IsNotExist(stateErr) && os.IsNotExist(pendingErr) {
		return nil
	}
	entries := map[string]int64{}
	for _, row := range rows {
		old, ok := entries[row.IP]
		if !ok || row.ExpireTime == 0 || old != 0 && row.ExpireTime > old {
			entries[row.IP] = row.ExpireTime
		}
	}
	return receiver.fw.SyncTimedBlocks(entries)
}

// mutateKernel 先在事务内变更持久账本，完整内核表发布成功才提交；失败时重新读取已提交真相恢复。
func (receiver *WafFirewallIPBlockService) mutateKernel(change func(*gorm.DB) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	attempted := false
	err := global.GWAF_LOCAL_DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockKernelLedger(tx); err != nil {
			return err
		}
		if err := change(tx); err != nil {
			return err
		}
		attempted = true
		return receiver.kernelSnapshot(tx)
	})
	if err != nil && attempted {
		kernelReconcileNeeded.Store(true)
		retry, done := context.WithTimeout(context.Background(), 5*time.Second)
		_ = PeriodicSystemBanReconcile(retry, true)
		done()
	}
	return err
}

// validateKernelExpiry 防止把已过期的控制请求显示成新生效封禁。
func validateKernelExpiry(expiry int64) error {
	if expiry < 0 || expiry > 0 && expiry <= time.Now().Unix() {
		return errors.New("封禁期限已过或无效，请先修改期限")
	}
	return nil
}

// addKernelBlock 在数据库锁内判重和落账，避免并发添加导致重复有效记录。
func (receiver *WafFirewallIPBlockService) addKernelBlock(req request.WafFirewallIPBlockAddReq) error {
	if err := validateKernelExpiry(req.ExpireTime); err != nil {
		return err
	}
	return receiver.mutateKernel(func(tx *gorm.DB) error {
		var count int64
		if err := tx.Model(&model.FirewallIPBlock{}).Where("ip=? AND status=? AND (expire_time=0 OR expire_time>?)", req.IP, "active", time.Now().Unix()).Count(&count).Error; err != nil {
			return err
		}
		if count > 0 {
			return errors.New("该 IP 已存在有效封禁")
		}
		kind := req.BlockType
		if kind == "" {
			kind = "manual"
		}
		now := customtype.JsonTime(time.Now())
		row := model.FirewallIPBlock{BaseOrm: baseorm.BaseOrm{Id: uuid.GenUUID(), USER_CODE: global.GWAF_USER_CODE, Tenant_ID: global.GWAF_TENANT_ID, CREATE_TIME: now, UPDATE_TIME: now}, IP: req.IP, Reason: req.Reason, BlockType: kind, Status: "active", ExpireTime: req.ExpireTime, Remarks: req.Remarks}
		return tx.Create(&row).Error
	})
}

// modifyKernelBlock 锁定原记录后整体更新，地址、状态和期限一起反映到同一来源表交换中。
func (receiver *WafFirewallIPBlockService) modifyKernelBlock(req request.WafFirewallIPBlockEditReq) error {
	if req.Status != "active" && req.Status != "inactive" && req.Status != "pending" {
		return errors.New("封禁状态无效")
	}
	if req.Status == "active" {
		if err := validateKernelExpiry(req.ExpireTime); err != nil {
			return err
		}
	}
	return receiver.mutateKernel(func(tx *gorm.DB) error {
		var old model.FirewallIPBlock
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id=?", req.Id).First(&old).Error; err != nil {
			return err
		}
		return tx.Model(&old).Updates(map[string]interface{}{"host_code": "", "ip": req.IP, "reason": req.Reason, "block_type": req.BlockType, "status": req.Status, "expire_time": req.ExpireTime, "remarks": req.Remarks, "UPDATE_TIME": customtype.JsonTime(time.Now())}).Error
	})
}

// changeKernelBlockStatus 只有内核更新确认后，active/inactive 状态才随事务提交。
func (receiver *WafFirewallIPBlockService) changeKernelBlockStatus(id, status string) error {
	return receiver.mutateKernel(func(tx *gorm.DB) error {
		var row model.FirewallIPBlock
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id=?", id).First(&row).Error; err != nil {
			return err
		}
		if status == "active" {
			if err := validateBlockIP(row.IP); err != nil {
				return err
			}
			if err := validateKernelExpiry(row.ExpireTime); err != nil {
				return err
			}
		}
		return tx.Model(&row).Updates(map[string]interface{}{"status": status, "UPDATE_TIME": customtype.JsonTime(time.Now())}).Error
	})
}

// PeriodicSystemBanReconcile 每 30 秒或失败后核对一次手工来源，恢复崩溃/提交失败后的不确定操作。
// 不确定时保留旧策略和错误，数据库不可用不能被解释成空名单。
func PeriodicSystemBanReconcile(ctx context.Context, force bool) error {
	if runtime.GOOS != "linux" || !force && !kernelReconcileNeeded.Load() {
		return nil
	}
	err := global.GWAF_LOCAL_DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockKernelLedger(tx); err != nil {
			return err
		}
		return WafFirewallIPBlockServiceApp.kernelSnapshot(tx)
	})
	if err == nil {
		kernelReconcileNeeded.Store(false)
	} else {
		kernelReconcileNeeded.Store(true)
	}
	return err
}
