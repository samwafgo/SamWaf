package waf_service

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafhealth"
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
)

type WafHealthService struct{}

var WafHealthServiceApp = new(WafHealthService)
var healthTestSlots = make(chan struct{}, 4)

type HealthTestResponse struct {
	Results    []wafhealth.Result `json:"results"`
	Total      int                `json:"total"`
	NextOffset int                `json:"next_offset"`
}

type healthTestTarget struct {
	id   string
	ip   string
	port int
}

func (s *WafHealthService) Test(ctx context.Context, req request.WafHostHealthTestReq, cfg model.HealthyConfig, runtime ...*wafenginmodel.SafeServerMap) (HealthTestResponse, error) {
	result := HealthTestResponse{Results: []wafhealth.Result{}, NextOffset: -1}
	if req.Limit < 1 || req.Limit > 5 || req.Offset < 0 {
		return result, errors.New("健康检测分页范围不合法")
	}
	select {
	case healthTestSlots <- struct{}{}:
		defer func() { <-healthTestSlots }()
	default:
		return result, errors.New("健康检测测试繁忙，请稍后重试")
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if req.Code != "" {
		var count int64
		err := global.GWAF_LOCAL_DB.WithContext(ctx).Model(&model.Hosts{}).
			Where("code = ? AND tenant_id = ? AND user_code = ?", req.Code, global.GWAF_TENANT_ID, global.GWAF_USER_CODE).Count(&count).Error
		if err != nil {
			return result, errors.New("读取网站失败")
		}
		if count == 0 {
			return result, errors.New("网站不存在")
		}
	}
	host := model.Hosts{Code: req.Code, Host: req.Host, Remote_host: req.RemoteHost, Remote_ip: req.RemoteIP,
		Remote_port: req.RemotePort, IsEnableLoadBalance: req.IsEnableLoadBalance, IsTransBackDomain: req.IsTransBackDomain}
	var targets []healthTestTarget
	if req.IsEnableLoadBalance == 1 {
		if req.Code == "" {
			return result, errors.New("请先保存网站并配置负载均衡后端")
		}
		query := global.GWAF_LOCAL_DB.WithContext(ctx).Model(&model.LoadBalance{}).
			Where("host_code = ? AND tenant_id = ? AND user_code = ?", req.Code, global.GWAF_TENANT_ID, global.GWAF_USER_CODE)
		var total int64
		if err := query.Count(&total).Error; err != nil {
			return result, errors.New("读取负载均衡后端失败")
		}
		result.Total = int(total)
		if total == 0 {
			return result, errors.New("请先配置负载均衡后端")
		}
		var backends []model.LoadBalance
		if err := query.Order("create_time asc").Order("id asc").Offset(req.Offset).Limit(req.Limit).Find(&backends).Error; err != nil {
			return result, errors.New("读取负载均衡后端失败")
		}
		for i, backend := range backends {
			targets = append(targets, healthTestTarget{strconv.Itoa(req.Offset + i), backend.Remote_ip, backend.Remote_port})
		}
	} else {
		result.Total = 1
		if req.Offset == 0 {
			targets = []healthTestTarget{{"single", req.RemoteIP, req.RemotePort}}
		}
	}
	guard, err := newHealthDialGuard(runtime...)
	if err != nil {
		return result, err
	}
	result.Results = make([]wafhealth.Result, len(targets))
	var wg sync.WaitGroup
	for i, target := range targets {
		wg.Add(1)
		go func(index int, target healthTestTarget) {
			defer wg.Done()
			if target.port < 1 || target.port > 65535 || (req.IsEnableLoadBalance == 1 && net.ParseIP(target.ip) == nil) {
				result.Results[index] = wafhealth.Result{BackendID: target.id, BackIP: target.ip, BackPort: target.port, Outcome: "skipped", ErrorReason: "后端IP或端口不合法"}
				return
			}
			result.Results[index] = wafhealth.ProbeWithDialGuard(ctx, host, target.ip, target.port, cfg, target.id, guard)
		}(i, target)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if next := req.Offset + len(targets); next < result.Total && len(targets) > 0 {
		result.NextOffset = next
	}
	return result, nil
}
