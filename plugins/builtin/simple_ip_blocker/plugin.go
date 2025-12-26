package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	plugininterface "SamWaf/plugin/interface"
	"SamWaf/plugins/common/logger"
)

// SimpleIPBlockerPlugin 简单的IP屏蔽插件
// 功能：屏蔽指定的IP地址
type SimpleIPBlockerPlugin struct {
	name        string
	version     string
	description string
	blockedIPs  map[string]string // IP -> 屏蔽原因
	logger      *logger.Logger    // 日志记录器
}

// NewSimpleIPBlockerPlugin 创建插件实例
func NewSimpleIPBlockerPlugin() *SimpleIPBlockerPlugin {
	plugin := &SimpleIPBlockerPlugin{
		name:        "Simple IP Blocker",
		version:     "1.0.0",
		description: "屏蔽指定的IP地址",
		blockedIPs: map[string]string{
			"8.8.8.8": "Google DNS - 示例屏蔽",
		},
	}

	return plugin
}

// ============ 实现 Plugin 基础接口 ============

// Name 返回插件名称
func (p *SimpleIPBlockerPlugin) Name() string {
	return p.name
}

// Version 返回插件版本
func (p *SimpleIPBlockerPlugin) Version() string {
	return p.version
}

// Type 返回插件类型
func (p *SimpleIPBlockerPlugin) Type() string {
	return "ip_filter"
}

// Init 初始化插件
func (p *SimpleIPBlockerPlugin) Init(config map[string]interface{}) error {
	fmt.Printf("[%s] 插件初始化中，配置项数量: %d\n", p.name, len(config))

	// 初始化日志系统
	// 获取当前工作目录（主程序的工作目录）
	workDir, err := os.Getwd()
	if err != nil {
		fmt.Printf("[%s] 警告: 获取工作目录失败: %v，使用默认路径\n", p.name, err)
		workDir = "."
	}

	// 构建日志目录的绝对路径
	logDir := filepath.Join(workDir, "data", "plugins", "logs")

	// 创建日志记录器
	pluginLogger, err := logger.NewLogger(
		p.name,                  // 插件名称
		logDir,                  // 日志目录
		"simple_ip_blocker_001", // 插件ID
	)
	if err != nil {
		fmt.Printf("[%s] 警告: 日志初始化失败: %v，将使用 fmt 输出\n", p.name, err)
	} else {
		p.logger = pluginLogger
		p.logger.Info("插件初始化开始", "config_keys", len(config))
	}

	// 从配置中读取要屏蔽的IP列表
	if blockedIPs, ok := config["blocked_ips"].([]interface{}); ok {
		if p.logger != nil {
			p.logger.Info("从配置读取屏蔽IP列表", "count", len(blockedIPs))
		} else {
			fmt.Printf("[%s] 从配置读取屏蔽IP列表，数量: %d\n", p.name, len(blockedIPs))
		}

		for _, ip := range blockedIPs {
			if ipStr, ok := ip.(string); ok {
				p.blockedIPs[ipStr] = "配置中指定的屏蔽IP"
				if p.logger != nil {
					p.logger.Info("添加屏蔽IP", "ip", ipStr)
				} else {
					fmt.Printf("[%s] 添加屏蔽IP: %s\n", p.name, ipStr)
				}
			}
		}
	}

	// 从配置中读取自定义屏蔽原因
	if reason, ok := config["block_reason"].(string); ok && reason != "" {
		// 更新所有IP的屏蔽原因
		for ip := range p.blockedIPs {
			p.blockedIPs[ip] = reason
		}
		if p.logger != nil {
			p.logger.Info("更新屏蔽原因", "reason", reason)
		} else {
			fmt.Printf("[%s] 更新屏蔽原因: %s\n", p.name, reason)
		}
	}

	if p.logger != nil {
		p.logger.Info("插件初始化完成", "blocked_ip_count", len(p.blockedIPs))
	} else {
		fmt.Printf("[%s] 初始化完成，当前屏蔽 %d 个IP\n", p.name, len(p.blockedIPs))
	}
	return nil
}

// Shutdown 关闭插件
func (p *SimpleIPBlockerPlugin) Shutdown() error {
	if p.logger != nil {
		p.logger.Info("插件关闭中...")
	} else {
		fmt.Printf("[%s] 插件关闭中...\n", p.name)
	}

	p.blockedIPs = make(map[string]string)

	if p.logger != nil {
		p.logger.Info("插件已关闭")
		if err := p.logger.Close(); err != nil {
			return fmt.Errorf("关闭日志失败: %w", err)
		}
	} else {
		fmt.Printf("[%s] 插件已关闭\n", p.name)
	}

	return nil
}

// HealthCheck 健康检查
func (p *SimpleIPBlockerPlugin) HealthCheck(ctx context.Context) error {
	// 简单的健康检查，确认插件运行正常
	if p.blockedIPs == nil {
		return fmt.Errorf("插件未初始化")
	}
	return nil
}

// ============ 实现 IPFilterPlugin 接口 ============

// Filter 执行IP过滤
func (p *SimpleIPBlockerPlugin) Filter(ctx context.Context, req *plugininterface.IPFilterRequest) (*plugininterface.IPFilterResponse, error) {
	ip := req.IP

	if p.logger != nil {
		p.logger.Debug("开始IP过滤检查", "ip", ip, "path", req.RequestPath, "user_agent", req.UserAgent)
	} else {
		fmt.Printf("[%s] 检查IP: %s, 路径: %s\n", p.name, ip, req.RequestPath)
	}

	// 检查IP是否在屏蔽列表中
	if reason, blocked := p.blockedIPs[ip]; blocked {
		if p.logger != nil {
			p.logger.Warn("⛔ IP被屏蔽", "ip", ip, "reason", reason, "path", req.RequestPath)
		} else {
			fmt.Printf("[%s] ⛔ 屏蔽IP: %s, 原因: %s\n", p.name, ip, reason)
		}

		return &plugininterface.IPFilterResponse{
			Allowed:   false,
			Reason:    fmt.Sprintf("IP已被屏蔽: %s", reason),
			RiskLevel: 8, // 风险等级 0-10，8表示高风险
		}, nil
	}

	// IP不在屏蔽列表，允许通过
	if p.logger != nil {
		p.logger.Debug("✅ IP检查通过", "ip", ip)
	} else {
		fmt.Printf("[%s] ✅ 允许IP: %s\n", p.name, ip)
	}

	return &plugininterface.IPFilterResponse{
		Allowed:   true,
		Reason:    "IP检查通过",
		RiskLevel: 0,
	}, nil
}

// ============ 实现 WafCheckPlugin 接口（支持WAF检查） ============

// Check 执行WAF检查
func (p *SimpleIPBlockerPlugin) Check(ctx context.Context, req *plugininterface.WafCheckRequest) (*plugininterface.WafCheckResponse, error) {
	ip := req.IP

	if p.logger != nil {
		p.logger.Debug("开始WAF检查", "ip", ip, "url", req.URL, "method", req.Method)
	} else {
		fmt.Printf("[%s] WAF检查 - IP: %s, URL: %s\n", p.name, ip, req.URL)
	}

	// 检查IP是否在屏蔽列表中
	if reason, blocked := p.blockedIPs[ip]; blocked {
		if p.logger != nil {
			p.logger.Warn("⛔ WAF拦截", "ip", ip, "url", req.URL, "reason", reason)
		} else {
			fmt.Printf("[%s] ⛔ WAF拦截 - IP: %s, 原因: %s\n", p.name, ip, reason)
		}

		return &plugininterface.WafCheckResponse{
			Allowed:   false,
			Reason:    fmt.Sprintf("IP已被屏蔽: %s", reason),
			RiskLevel: 8,
			Action:    "block", // 建议动作：拦截
			Extra: map[string]interface{}{
				"blocked_ip": ip,
				"plugin":     p.name,
			},
		}, nil
	}

	// IP允许通过
	if p.logger != nil {
		p.logger.Debug("✅ WAF检查通过", "ip", ip, "url", req.URL)
	} else {
		fmt.Printf("[%s] ✅ WAF通过 - IP: %s\n", p.name, ip)
	}

	return &plugininterface.WafCheckResponse{
		Allowed:   true,
		Reason:    "IP检查通过",
		RiskLevel: 0,
		Action:    "allow",
		Extra: map[string]interface{}{
			"checked_ip": ip,
			"plugin":     p.name,
		},
	}, nil
}

// ============ 辅助方法 ============

// AddBlockedIP 动态添加要屏蔽的IP
func (p *SimpleIPBlockerPlugin) AddBlockedIP(ip string, reason string) {
	p.blockedIPs[ip] = reason
	if p.logger != nil {
		p.logger.Info("添加屏蔽IP", "ip", ip, "reason", reason)
	} else {
		fmt.Printf("[%s] 添加屏蔽IP: %s, 原因: %s\n", p.name, ip, reason)
	}
}

// RemoveBlockedIP 移除屏蔽的IP
func (p *SimpleIPBlockerPlugin) RemoveBlockedIP(ip string) {
	if _, exists := p.blockedIPs[ip]; exists {
		delete(p.blockedIPs, ip)
		if p.logger != nil {
			p.logger.Info("移除屏蔽IP", "ip", ip)
		} else {
			fmt.Printf("[%s] 移除屏蔽IP: %s\n", p.name, ip)
		}
	}
}

// GetBlockedIPs 获取所有屏蔽的IP列表
func (p *SimpleIPBlockerPlugin) GetBlockedIPs() map[string]string {
	return p.blockedIPs
}

// IsBlocked 检查IP是否被屏蔽
func (p *SimpleIPBlockerPlugin) IsBlocked(ip string) (bool, string) {
	reason, blocked := p.blockedIPs[ip]
	return blocked, reason
}
