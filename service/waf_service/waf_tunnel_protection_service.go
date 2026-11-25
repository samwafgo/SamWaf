package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"context"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"time"

	"gorm.io/gorm"
)

var (
	ErrTunnelProtectionConflict = errors.New("隧道访问配置已变化，请重新加载后再保存")
	ErrTunnelWhitelistConfirm   = errors.New("此操作将关闭白名单检查，请确认后再保存")
	ErrTunnelDDNSBinding        = errors.New("动态域名绑定已变化，请重新加载后再保存")
)

type TunnelProtectionConfig struct {
	Tunnel model.Tunnel
	Region model.TunnelRegionProtection
	DDNS   model.TunnelDDNSProtection
}

func tunnelProtectionQuery(db *gorm.DB, id string) *gorm.DB {
	return db.Model(&model.Tunnel{}).Where("id = ? AND tenant_id = ? AND user_code = ?", id, global.GWAF_TENANT_ID, global.GWAF_USER_CODE)
}

func loadTunnelProtection(db *gorm.DB, id string) (TunnelProtectionConfig, error) {
	var config TunnelProtectionConfig
	if err := tunnelProtectionQuery(db, id).Take(&config.Tunnel).Error; err != nil {
		return config, err
	}
	config.Region = model.TunnelRegionProtection{Fallback: "allow", Unknown: "allow", Rules: []model.TunnelRegionRule{}}
	if config.Tunnel.RegionProtection != "" {
		if err := json.Unmarshal([]byte(config.Tunnel.RegionProtection), &config.Region); err != nil {
			return config, err
		}
	}
	if config.Region.Rules == nil {
		config.Region.Rules = []model.TunnelRegionRule{}
	}
	config.DDNS.Bindings = []model.TunnelDDNSBinding{}
	if config.Tunnel.DDNSProtection != "" {
		if err := json.Unmarshal([]byte(config.Tunnel.DDNSProtection), &config.DDNS); err != nil {
			return config, err
		}
	}
	if config.DDNS.Bindings == nil {
		config.DDNS.Bindings = []model.TunnelDDNSBinding{}
	}
	return config, nil
}

func (receiver *WafTunnelService) GetProtection(ctx context.Context, id string) (TunnelProtectionConfig, error) {
	return loadTunnelProtection(global.GWAF_LOCAL_DB.WithContext(ctx), id)
}

func HasEnabledTunnelDDNS(bindings []model.TunnelDDNSBinding) bool {
	return slices.ContainsFunc(bindings, func(binding model.TunnelDDNSBinding) bool { return binding.Enabled })
}

func (receiver *WafTunnelService) SaveRegionProtection(ctx context.Context, id string, next model.TunnelRegionProtection) (before, after TunnelProtectionConfig, err error) {
	db := global.GWAF_LOCAL_DB.WithContext(ctx)
	err = db.Transaction(func(tx *gorm.DB) error {
		var loadErr error
		before, loadErr = loadTunnelProtection(tx, id)
		if loadErr != nil {
			return loadErr
		}
		if next.Revision != before.Region.Revision || next.Revision == math.MaxInt64 {
			return ErrTunnelProtectionConflict
		}
		after = before
		if before.Region.Enabled == next.Enabled && before.Region.Fallback == next.Fallback && before.Region.Unknown == next.Unknown && slices.Equal(before.Region.Rules, next.Rules) {
			return nil
		}
		next.Revision++
		raw, marshalErr := json.Marshal(next)
		if marshalErr != nil {
			return marshalErr
		}
		query := tunnelProtectionQuery(tx, id)
		if before.Tunnel.RegionProtection == "" {
			query = query.Where("region_protection IS NULL OR region_protection = ?", "")
		} else {
			query = query.Where("region_protection = ?", before.Tunnel.RegionProtection)
		}
		updated := query.Updates(map[string]any{"region_protection": string(raw), "update_time": customtype.JsonTime(time.Now())})
		if updated.Error != nil {
			return updated.Error
		}
		if updated.RowsAffected != 1 {
			return ErrTunnelProtectionConflict
		}
		after, loadErr = loadTunnelProtection(tx, id)
		return loadErr
	})
	return
}

func (receiver *WafTunnelService) SaveDDNSProtection(ctx context.Context, id string, next model.TunnelDDNSProtection, confirmDisable bool) (before, after TunnelProtectionConfig, err error) {
	db := global.GWAF_LOCAL_DB.WithContext(ctx)
	err = db.Transaction(func(tx *gorm.DB) error {
		var loadErr error
		before, loadErr = loadTunnelProtection(tx, id)
		if loadErr != nil {
			return loadErr
		}
		if next.Revision != before.DDNS.Revision || next.Revision == math.MaxInt64 {
			return ErrTunnelProtectionConflict
		}
		after = before
		if slices.Equal(before.DDNS.Bindings, next.Bindings) {
			return nil
		}
		removesLast := HasEnabledTunnelDDNS(before.DDNS.Bindings) && !HasEnabledTunnelDDNS(next.Bindings)
		if removesLast && before.Tunnel.AllowIp == "" && !confirmDisable {
			return ErrTunnelWhitelistConfirm
		}
		bindings := slices.Clone(next.Bindings)
		for i := range bindings {
			if bindings[i].ID == "" {
				bindings[i].ID = uuid.GenUUID()
			} else if !slices.ContainsFunc(before.DDNS.Bindings, func(binding model.TunnelDDNSBinding) bool { return binding.ID == bindings[i].ID }) {
				return ErrTunnelDDNSBinding
			}
		}
		next.Bindings = bindings
		next.Revision++
		raw, marshalErr := json.Marshal(next)
		if marshalErr != nil {
			return marshalErr
		}
		query := tunnelProtectionQuery(tx, id)
		if before.Tunnel.DDNSProtection == "" {
			query = query.Where("ddns_protection IS NULL OR ddns_protection = ?", "")
		} else {
			query = query.Where("ddns_protection = ?", before.Tunnel.DDNSProtection)
		}
		if removesLast && !confirmDisable {
			query = query.Where("allow_ip = ?", before.Tunnel.AllowIp)
		}
		updated := query.Updates(map[string]any{"ddns_protection": string(raw), "update_time": customtype.JsonTime(time.Now())})
		if updated.Error != nil {
			return updated.Error
		}
		if updated.RowsAffected != 1 {
			return ErrTunnelProtectionConflict
		}
		after, loadErr = loadTunnelProtection(tx, id)
		return loadErr
	})
	return
}
