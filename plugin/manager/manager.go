package manager

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	pluginconfig "SamWaf/plugin/config"
	plugininterface "SamWaf/plugin/interface"
	"SamWaf/plugin/registry"
	"SamWaf/plugin/shared"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
)

// PluginInstance 插件实例
type PluginInstance struct {
	ID           string                     // 插件ID
	Name         string                     // 插件名称
	Type         string                     // 插件类型
	Version      string                     // 版本
	Enabled      bool                       // 是否启用
	Priority     int                        // 优先级
	Groups       []string                   // 分组
	Plugin       plugininterface.Plugin     // 插件接口
	Config       map[string]interface{}     // 插件配置
	Client       *plugin.Client             // go-plugin 客户端（用于管理插件进程）
	PluginConfig *pluginconfig.PluginConfig // 插件配置（用于重启）
	RestartCount int                        // 重启次数
}

// PluginManager 插件管理器
type PluginManager struct {
	mu           sync.RWMutex
	enabled      bool                             // 插件系统是否启用
	plugins      map[string]*PluginInstance       // 已加载的插件 key: plugin ID
	registry     *registry.Registry               // 插件注册表
	config       *pluginconfig.PluginSystemConfig // 系统配置
	stopChan     chan struct{}                    // 停止信号
	healthTicker *time.Ticker                     // 健康检查定时器
}

// NewPluginManager 创建插件管理器
func NewPluginManager(config *pluginconfig.PluginSystemConfig) *PluginManager {
	if config == nil {
		config = pluginconfig.DefaultPluginSystemConfig()
	}

	pm := &PluginManager{
		enabled:  config.Enabled,
		plugins:  make(map[string]*PluginInstance),
		registry: registry.NewRegistry(),
		config:   config,
		stopChan: make(chan struct{}),
	}

	// 如果启用自动重启，启动健康检查
	if config.AutoRestart && config.HealthCheckInterval > 0 {
		pm.startHealthCheck()
	}

	return pm
}

// IsEnabled 检查插件系统是否启用
func (pm *PluginManager) IsEnabled() bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.enabled
}

// SetEnabled 设置插件系统启用状态
func (pm *PluginManager) SetEnabled(enabled bool) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.enabled = enabled
}

// LoadPlugin 加载插件
func (pm *PluginManager) LoadPlugin(pluginConfig *pluginconfig.PluginConfig) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// 检查插件是否已加载
	if _, exists := pm.plugins[pluginConfig.ID]; exists {
		return fmt.Errorf("plugin already loaded: %s", pluginConfig.ID)
	}

	// 创建 go-plugin 客户端
	fmt.Printf("[DEBUG] 正在创建插件客户端: %s\n", pluginConfig.ID)
	fmt.Printf("[DEBUG] 插件路径: %s\n", pluginConfig.BinaryPath)

	// 解析日志级别
	logLevel, logOutput := parseLogLevel(pm.config.LogLevel)

	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: shared.Handshake,
		Plugins:         shared.PluginMap,
		Cmd:             exec.Command(pluginConfig.BinaryPath),
		AllowedProtocols: []plugin.Protocol{
			plugin.ProtocolGRPC,
		},
		Logger: hclog.New(&hclog.LoggerOptions{
			Name:   pluginConfig.ID,
			Output: logOutput, // 根据级别决定输出位置
			Level:  logLevel,  // 使用配置的日志级别
		}),
	})

	fmt.Printf("[DEBUG] 插件客户端已创建，正在连接...\n")

	// 连接到插件
	rpcClient, err := client.Client()
	if err != nil {
		fmt.Printf("[ERROR] 连接插件失败: %v\n", err)
		client.Kill()
		return fmt.Errorf("failed to get RPC client for plugin %s: %w", pluginConfig.ID, err)
	}

	fmt.Printf("[DEBUG] 已连接到插件，正在请求接口...\n")

	// 请求插件接口
	raw, err := rpcClient.Dispense("ip_filter")
	if err != nil {
		fmt.Printf("[ERROR] Dispense 插件失败: %v\n", err)
		client.Kill()
		return fmt.Errorf("failed to dispense plugin %s: %w", pluginConfig.ID, err)
	}

	fmt.Printf("[DEBUG] 已获取插件接口，类型: %T\n", raw)

	// 类型断言为插件接口
	pluginImpl, ok := raw.(plugininterface.IPFilterPlugin)
	if !ok {
		fmt.Printf("[ERROR] 类型断言失败，实际类型: %T\n", raw)
		client.Kill()
		return fmt.Errorf("plugin %s does not implement IPFilterPlugin interface", pluginConfig.ID)
	}

	fmt.Printf("[DEBUG] 类型断言成功，正在初始化插件...\n")

	// 初始化插件
	if err := pluginImpl.Init(pluginConfig.Params); err != nil {
		fmt.Printf("[ERROR] 初始化插件失败: %v\n", err)
		client.Kill()
		return fmt.Errorf("failed to initialize plugin %s: %w", pluginConfig.ID, err)
	}

	fmt.Printf("[DEBUG] 插件初始化成功！\n")

	// 创建插件实例
	instance := &PluginInstance{
		ID:           pluginConfig.ID,
		Name:         pluginConfig.Name,
		Type:         pluginConfig.Type,
		Version:      pluginConfig.Version,
		Enabled:      pluginConfig.Enabled,
		Priority:     pluginConfig.Priority,
		Groups:       pluginConfig.Groups,
		Config:       pluginConfig.Params,
		Plugin:       pluginImpl,   // 实际的插件实例（通过 gRPC 通信）
		Client:       client,       // 保存客户端以便后续关闭
		PluginConfig: pluginConfig, // 保存配置以便重启
		RestartCount: 0,            // 初始重启次数为 0
	}

	pm.plugins[pluginConfig.ID] = instance

	// 注册到注册表
	regInfo := &registry.PluginInfo{
		ID:       pluginConfig.ID,
		Name:     pluginConfig.Name,
		Type:     pluginConfig.Type,
		Version:  pluginConfig.Version,
		Priority: pluginConfig.Priority,
		Groups:   pluginConfig.Groups,
		Enabled:  pluginConfig.Enabled,
	}

	return pm.registry.Register(regInfo)
}

// UnloadPlugin 卸载插件
func (pm *PluginManager) UnloadPlugin(pluginID string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	instance, exists := pm.plugins[pluginID]
	if !exists {
		return fmt.Errorf("plugin not found: %s", pluginID)
	}

	// 关闭插件
	if instance.Plugin != nil {
		if err := instance.Plugin.Shutdown(); err != nil {
			return fmt.Errorf("failed to shutdown plugin: %w", err)
		}
	}

	// 杀死插件进程
	if instance.Client != nil {
		instance.Client.Kill()
	}

	// 从映射中删除
	delete(pm.plugins, pluginID)

	// 从注册表注销
	return pm.registry.Unregister(pluginID)
}

// GetPlugin 获取插件
func (pm *PluginManager) GetPlugin(pluginID string) (*PluginInstance, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	instance, exists := pm.plugins[pluginID]
	if !exists {
		return nil, fmt.Errorf("plugin not found: %s", pluginID)
	}

	return instance, nil
}

// GetPluginsByGroup 根据分组获取插件
func (pm *PluginManager) GetPluginsByGroup(group string) []*PluginInstance {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var instances []*PluginInstance
	for _, instance := range pm.plugins {
		if instance.Enabled && contains(instance.Groups, group) {
			instances = append(instances, instance)
		}
	}

	// 按优先级排序（优先级高的在前）
	sort.Slice(instances, func(i, j int) bool {
		return instances[i].Priority > instances[j].Priority
	})

	return instances
}

// GetAllPlugins 获取所有插件
func (pm *PluginManager) GetAllPlugins() []*PluginInstance {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	instances := make([]*PluginInstance, 0, len(pm.plugins))
	for _, instance := range pm.plugins {
		instances = append(instances, instance)
	}

	return instances
}

// CallWafCheck 调用WAF检查插件
func (pm *PluginManager) CallWafCheck(ctx context.Context, pluginID string, req *plugininterface.WafCheckRequest) (*plugininterface.WafCheckResponse, error) {
	instance, err := pm.GetPlugin(pluginID)
	if err != nil {
		return nil, err
	}

	if !instance.Enabled {
		return nil, fmt.Errorf("plugin is disabled: %s", pluginID)
	}

	if instance.Plugin == nil {
		return nil, fmt.Errorf("plugin not initialized: %s", pluginID)
	}

	wafPlugin, ok := instance.Plugin.(plugininterface.WafCheckPlugin)
	if !ok {
		return nil, fmt.Errorf("plugin is not a WafCheckPlugin: %s", pluginID)
	}

	return wafPlugin.Check(ctx, req)
}

// CallWafCheckByGroup 调用指定分组的所有WAF检查插件
func (pm *PluginManager) CallWafCheckByGroup(ctx context.Context, group string, req *plugininterface.WafCheckRequest) ([]*plugininterface.WafCheckResponse, error) {
	instances := pm.GetPluginsByGroup(group)

	var responses []*plugininterface.WafCheckResponse
	for _, instance := range instances {
		// 跳过未初始化的插件
		if instance.Plugin == nil {
			continue
		}

		wafPlugin, ok := instance.Plugin.(plugininterface.WafCheckPlugin)
		if !ok {
			continue
		}

		resp, err := wafPlugin.Check(ctx, req)
		if err != nil {
			// 记录错误但继续执行其他插件
			// TODO: 添加日志记录
			continue
		}

		responses = append(responses, resp)

		// 如果某个插件返回不允许，可以选择立即返回或继续执行
		// 这里继续执行所有插件，让调用者决定如何处理
	}

	return responses, nil
}

// CallIPFilter 调用IP过滤插件
func (pm *PluginManager) CallIPFilter(ctx context.Context, pluginID string, req *plugininterface.IPFilterRequest) (*plugininterface.IPFilterResponse, error) {
	instance, err := pm.GetPlugin(pluginID)
	if err != nil {
		return nil, err
	}

	if !instance.Enabled {
		return nil, fmt.Errorf("plugin is disabled: %s", pluginID)
	}

	if instance.Plugin == nil {
		return nil, fmt.Errorf("plugin not initialized: %s", pluginID)
	}

	ipPlugin, ok := instance.Plugin.(plugininterface.IPFilterPlugin)
	if !ok {
		return nil, fmt.Errorf("plugin is not an IPFilterPlugin: %s", pluginID)
	}

	return ipPlugin.Filter(ctx, req)
}

// CallIPFilterByGroup 调用指定分组的所有IP过滤插件
func (pm *PluginManager) CallIPFilterByGroup(ctx context.Context, group string, req *plugininterface.IPFilterRequest) ([]*plugininterface.IPFilterResponse, error) {
	instances := pm.GetPluginsByGroup(group)

	var responses []*plugininterface.IPFilterResponse
	for _, instance := range instances {
		// 跳过未初始化的插件
		if instance.Plugin == nil {
			continue
		}

		ipPlugin, ok := instance.Plugin.(plugininterface.IPFilterPlugin)
		if !ok {
			continue
		}

		resp, err := ipPlugin.Filter(ctx, req)
		if err != nil {
			// 记录错误但继续执行其他插件
			continue
		}

		responses = append(responses, resp)
	}

	return responses, nil
}

// ReloadPlugin 重新加载插件
func (pm *PluginManager) ReloadPlugin(pluginID string) error {
	// TODO: 实现重新加载逻辑
	// 1. 卸载插件
	// 2. 重新从配置加载
	// 3. 初始化插件
	return fmt.Errorf("reload plugin not implemented yet")
}

// CheckRequest 通用请求检查方法（供 WAF 引擎调用）
// 返回：isBlock bool, reason string
func (pm *PluginManager) CheckRequest(ctx context.Context, group string, ip string, requestPath string, userAgent string, method string, host string) (bool, string) {
	// 检查插件系统是否启用
	if !pm.IsEnabled() {
		return false, ""
	}

	// 获取该分组的插件
	instances := pm.GetPluginsByGroup(group)
	if len(instances) == 0 {
		return false, ""
	}

	// 构造请求
	req := &plugininterface.IPFilterRequest{
		IP:          ip,
		RequestPath: requestPath,
		UserAgent:   userAgent,
		Extra: map[string]interface{}{
			"method": method,
			"host":   host,
		},
	}

	// 调用每个插件
	for _, instance := range instances {
		// 跳过未初始化的插件
		if instance.Plugin == nil {
			continue
		}

		// 尝试作为 IPFilterPlugin 调用
		if ipPlugin, ok := instance.Plugin.(plugininterface.IPFilterPlugin); ok {
			resp, err := ipPlugin.Filter(ctx, req)
			if err != nil {
				// 记录错误但继续
				fmt.Printf("plugin %s filter error: %v\n", instance.ID, err)
				continue
			}

			// 如果插件返回不允许，立即返回拦截
			if resp != nil && !resp.Allowed {
				return true, fmt.Sprintf("[插件:%s] %s", instance.Name, resp.Reason)
			}
		}

		// 可以继续添加其他类型的插件调用（WafCheckPlugin 等）
	}

	// 所有插件都通过，不拦截
	return false, ""
}

// Shutdown 关闭所有插件
func (pm *PluginManager) Shutdown() error {
	// 停止健康检查
	close(pm.stopChan)
	if pm.healthTicker != nil {
		pm.healthTicker.Stop()
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	fmt.Printf("[PluginManager] 正在关闭所有插件，共 %d 个\n", len(pm.plugins))

	for id, instance := range pm.plugins {
		fmt.Printf("[PluginManager] 关闭插件: %s\n", id)

		// 调用插件的 Shutdown 方法
		if instance.Plugin != nil {
			if err := instance.Plugin.Shutdown(); err != nil {
				fmt.Printf("[PluginManager] 警告: 插件 %s 关闭失败: %v\n", id, err)
			} else {
				fmt.Printf("[PluginManager] 插件 %s 已正常关闭\n", id)
			}
		}

		// 杀死插件进程
		if instance.Client != nil {
			instance.Client.Kill()
			fmt.Printf("[PluginManager] 插件进程 %s 已终止\n", id)
		}
	}

	// 清空插件映射
	pm.plugins = make(map[string]*PluginInstance)
	fmt.Printf("[PluginManager] 所有插件已关闭\n")

	return nil
}

// contains 检查字符串是否在切片中
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// parseLogLevel 解析日志级别字符串
func parseLogLevel(levelStr string) (hclog.Level, io.Writer) {
	levelStr = strings.ToLower(strings.TrimSpace(levelStr))

	switch levelStr {
	case "off", "none":
		// 完全关闭日志输出
		return hclog.Off, io.Discard
	case "error":
		return hclog.Error, os.Stderr
	case "warn", "warning":
		return hclog.Warn, os.Stderr
	case "info":
		return hclog.Info, os.Stderr
	case "debug":
		return hclog.Debug, os.Stderr
	case "trace":
		return hclog.Trace, os.Stderr
	default:
		// 默认使用 warn 级别
		return hclog.Warn, os.Stderr
	}
}

// startHealthCheck 启动健康检查协程
func (pm *PluginManager) startHealthCheck() {
	interval := time.Duration(pm.config.HealthCheckInterval) * time.Second
	pm.healthTicker = time.NewTicker(interval)

	fmt.Printf("[PluginManager] 健康检查已启动，间隔: %d 秒\n", pm.config.HealthCheckInterval)

	go func() {
		for {
			select {
			case <-pm.stopChan:
				fmt.Printf("[PluginManager] 健康检查已停止\n")
				return
			case <-pm.healthTicker.C:
				pm.checkPluginHealth()
			}
		}
	}()
}

// checkPluginHealth 检查所有插件的健康状态
func (pm *PluginManager) checkPluginHealth() {
	pm.mu.RLock()
	pluginsToCheck := make(map[string]*PluginInstance)
	for id, instance := range pm.plugins {
		if instance.Enabled {
			pluginsToCheck[id] = instance
		}
	}
	pm.mu.RUnlock()

	for id, instance := range pluginsToCheck {
		if instance.Client != nil && instance.Client.Exited() {
			fmt.Printf("[PluginManager] 检测到插件 %s 已退出，准备重启\n", id)
			pm.restartPlugin(id, instance)
		}
	}
}

// restartPlugin 重启插件
func (pm *PluginManager) restartPlugin(pluginID string, instance *PluginInstance) {
	// 检查是否启用自动重启
	if !pm.config.AutoRestart {
		fmt.Printf("[PluginManager] 自动重启已禁用，插件 %s 不会重启\n", pluginID)
		return
	}

	// 检查重启次数限制
	if pm.config.MaxRestartCount >= 0 && instance.RestartCount >= pm.config.MaxRestartCount {
		fmt.Printf("[PluginManager] 插件 %s 已达到最大重启次数 (%d)，不再重启\n",
			pluginID, pm.config.MaxRestartCount)
		return
	}

	// 等待重启间隔
	if pm.config.RestartInterval > 0 {
		fmt.Printf("[PluginManager] 等待 %d 秒后重启插件 %s...\n",
			pm.config.RestartInterval, pluginID)
		time.Sleep(time.Duration(pm.config.RestartInterval) * time.Second)
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	// 再次检查插件是否还在映射中（可能已被手动卸载）
	currentInstance, exists := pm.plugins[pluginID]
	if !exists || currentInstance != instance {
		fmt.Printf("[PluginManager] 插件 %s 已被移除，取消重启\n", pluginID)
		return
	}

	fmt.Printf("[PluginManager] 正在重启插件 %s (第 %d 次重启)\n",
		pluginID, instance.RestartCount+1)

	// 清理旧的客户端
	if instance.Client != nil {
		instance.Client.Kill()
	}

	// 从映射中删除旧实例
	delete(pm.plugins, pluginID)

	// 从注册表中注销（重要！避免 "already registered" 错误）
	if err := pm.registry.Unregister(pluginID); err != nil {
		fmt.Printf("[PluginManager] 警告: 注销插件 %s 失败: %v\n", pluginID, err)
	}

	// 暂时释放锁以避免死锁
	pm.mu.Unlock()

	// 重新加载插件
	err := pm.LoadPlugin(instance.PluginConfig)

	// 重新获取锁
	pm.mu.Lock()

	if err != nil {
		fmt.Printf("[PluginManager] ❌ 插件 %s 重启失败: %v\n", pluginID, err)
		// 不恢复旧实例，因为它已经被清理且注销了
		// 如果需要继续尝试，下次健康检查会检测到插件不在映射中
		fmt.Printf("[PluginManager] 插件 %s 已从管理器中移除，重启计数: %d\n",
			pluginID, instance.RestartCount+1)
	} else {
		fmt.Printf("[PluginManager] ✅ 插件 %s 重启成功\n", pluginID)
		// 更新重启计数
		if newInstance, exists := pm.plugins[pluginID]; exists {
			newInstance.RestartCount = instance.RestartCount + 1
			fmt.Printf("[PluginManager] 插件 %s 重启计数已更新: %d\n",
				pluginID, newInstance.RestartCount)
		}
	}
}
