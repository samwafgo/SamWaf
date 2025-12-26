package api

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/globalobj"
	"SamWaf/model"
	"SamWaf/model/common/response"
	pluginconfig "SamWaf/plugin/config"
	"encoding/json"

	"github.com/gin-gonic/gin"
)

type WafPluginApi struct {
}

// GetListApi 获取插件列表
func (w *WafPluginApi) GetListApi(c *gin.Context) {
	var plugins []model.WafPluginConfig

	err := global.GWAF_LOCAL_DB.Find(&plugins).Error
	if err != nil {
		response.FailWithMessage("查询失败", c)
		return
	}

	response.OkWithDetailed(plugins, "获取成功", c)
}

// GetDetailApi 获取插件详情
func (w *WafPluginApi) GetDetailApi(c *gin.Context) {
	pluginID := c.Query("plugin_id")
	if pluginID == "" {
		response.FailWithMessage("插件ID不能为空", c)
		return
	}

	var plugin model.WafPluginConfig
	err := global.GWAF_LOCAL_DB.Where("plugin_id = ?", pluginID).First(&plugin).Error
	if err != nil {
		response.FailWithMessage("插件不存在", c)
		return
	}

	response.OkWithDetailed(plugin, "获取成功", c)
}

// AddApi 添加插件
func (w *WafPluginApi) AddApi(c *gin.Context) {
	var plugin model.WafPluginConfig

	err := c.ShouldBindJSON(&plugin)
	if err != nil {
		response.FailWithMessage("参数解析失败", c)
		return
	}

	// 检查插件ID是否已存在
	var count int64
	global.GWAF_LOCAL_DB.Model(&model.WafPluginConfig{}).Where("plugin_id = ?", plugin.PluginID).Count(&count)
	if count > 0 {
		response.FailWithMessage("插件ID已存在", c)
		return
	}

	// 保存到数据库
	err = global.GWAF_LOCAL_DB.Create(&plugin).Error
	if err != nil {
		response.FailWithMessage("添加失败", c)
		return
	}

	// 如果插件已启用，尝试加载
	if plugin.Enabled == 1 && globalobj.GWAF_RUNTIME_OBJ_PLUGIN_MANAGER != nil {
		config := w.convertToPluginConfig(&plugin)
		if err := globalobj.GWAF_RUNTIME_OBJ_PLUGIN_MANAGER.LoadPlugin(config); err != nil {
			zlog.Error("加载插件失败", "plugin_id", plugin.PluginID, "error", err)
			response.FailWithMessage("添加成功但加载失败: "+err.Error(), c)
			return
		}
	}

	response.OkWithMessage("添加成功", c)
}

// ModifyApi 修改插件
func (w *WafPluginApi) ModifyApi(c *gin.Context) {
	var plugin model.WafPluginConfig

	err := c.ShouldBindJSON(&plugin)
	if err != nil {
		response.FailWithMessage("参数解析失败", c)
		return
	}

	// 更新数据库
	err = global.GWAF_LOCAL_DB.Where("plugin_id = ?", plugin.PluginID).Updates(&plugin).Error
	if err != nil {
		response.FailWithMessage("更新失败", c)
		return
	}

	// 重新加载插件
	if globalobj.GWAF_RUNTIME_OBJ_PLUGIN_MANAGER != nil {
		// 先卸载旧插件
		globalobj.GWAF_RUNTIME_OBJ_PLUGIN_MANAGER.UnloadPlugin(plugin.PluginID)

		// 如果启用，重新加载
		if plugin.Enabled == 1 {
			config := w.convertToPluginConfig(&plugin)
			if err := globalobj.GWAF_RUNTIME_OBJ_PLUGIN_MANAGER.LoadPlugin(config); err != nil {
				zlog.Error("重新加载插件失败", "plugin_id", plugin.PluginID, "error", err)
			}
		}
	}

	response.OkWithMessage("更新成功", c)
}

// DeleteApi 删除插件
func (w *WafPluginApi) DeleteApi(c *gin.Context) {
	pluginID := c.Query("plugin_id")
	if pluginID == "" {
		response.FailWithMessage("插件ID不能为空", c)
		return
	}

	// 从数据库删除
	err := global.GWAF_LOCAL_DB.Where("plugin_id = ?", pluginID).Delete(&model.WafPluginConfig{}).Error
	if err != nil {
		response.FailWithMessage("删除失败", c)
		return
	}

	// 卸载插件
	if globalobj.GWAF_RUNTIME_OBJ_PLUGIN_MANAGER != nil {
		globalobj.GWAF_RUNTIME_OBJ_PLUGIN_MANAGER.UnloadPlugin(pluginID)
	}

	response.OkWithMessage("删除成功", c)
}

// ToggleApi 启用/禁用插件
func (w *WafPluginApi) ToggleApi(c *gin.Context) {
	pluginID := c.Query("plugin_id")
	if pluginID == "" {
		response.FailWithMessage("插件ID不能为空", c)
		return
	}

	// 查询插件
	var plugin model.WafPluginConfig
	err := global.GWAF_LOCAL_DB.Where("plugin_id = ?", pluginID).First(&plugin).Error
	if err != nil {
		response.FailWithMessage("插件不存在", c)
		return
	}

	// 切换状态
	newStatus := 0
	if plugin.Enabled == 0 {
		newStatus = 1
	}

	// 更新数据库
	err = global.GWAF_LOCAL_DB.Model(&plugin).Update("enabled", newStatus).Error
	if err != nil {
		response.FailWithMessage("更新失败", c)
		return
	}

	// 加载或卸载插件
	if globalobj.GWAF_RUNTIME_OBJ_PLUGIN_MANAGER != nil {
		if newStatus == 1 {
			// 启用：加载插件
			plugin.Enabled = 1
			config := w.convertToPluginConfig(&plugin)
			if err := globalobj.GWAF_RUNTIME_OBJ_PLUGIN_MANAGER.LoadPlugin(config); err != nil {
				zlog.Error("加载插件失败", "plugin_id", pluginID, "error", err)
				response.FailWithMessage("启用失败: "+err.Error(), c)
				return
			}
		} else {
			// 禁用：卸载插件
			globalobj.GWAF_RUNTIME_OBJ_PLUGIN_MANAGER.UnloadPlugin(pluginID)
		}
	}

	response.OkWithMessage("操作成功", c)
}

// GetSystemConfigApi 获取插件系统配置
func (w *WafPluginApi) GetSystemConfigApi(c *gin.Context) {
	var configs []model.WafPluginSystemConfig

	err := global.GWAF_LOCAL_DB.Find(&configs).Error
	if err != nil {
		response.FailWithMessage("查询失败", c)
		return
	}

	// 转换为map格式
	configMap := make(map[string]string)
	for _, config := range configs {
		configMap[config.Key] = config.Value
	}

	response.OkWithDetailed(configMap, "获取成功", c)
}

// UpdateSystemConfigApi 更新插件系统配置
func (w *WafPluginApi) UpdateSystemConfigApi(c *gin.Context) {
	var req map[string]string

	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.FailWithMessage("参数解析失败", c)
		return
	}

	// 更新配置
	for key, value := range req {
		var config model.WafPluginSystemConfig
		err := global.GWAF_LOCAL_DB.Where("key = ?", key).First(&config).Error
		if err == nil {
			// 更新
			global.GWAF_LOCAL_DB.Model(&config).Update("value", value)
		} else {
			// 创建
			config = model.WafPluginSystemConfig{
				Key:   key,
				Value: value,
			}
			global.GWAF_LOCAL_DB.Create(&config)
		}
	}

	// 如果修改了enabled，更新插件管理器状态
	if enabled, ok := req["enabled"]; ok && globalobj.GWAF_RUNTIME_OBJ_PLUGIN_MANAGER != nil {
		globalobj.GWAF_RUNTIME_OBJ_PLUGIN_MANAGER.SetEnabled(enabled == "1" || enabled == "true")
	}

	response.OkWithMessage("更新成功", c)
}

// GetPluginLogsApi 获取插件日志
func (w *WafPluginApi) GetPluginLogsApi(c *gin.Context) {
	pluginID := c.Query("plugin_id")
	page := c.DefaultQuery("page", "1")
	pageSize := c.DefaultQuery("page_size", "20")

	var logs []model.WafPluginLog
	query := global.GWAF_LOCAL_DB.Model(&model.WafPluginLog{})

	if pluginID != "" {
		query = query.Where("plugin_id = ?", pluginID)
	}

	// 分页
	var total int64
	query.Count(&total)

	var pageInt, pageSizeInt int
	json.Unmarshal([]byte(page), &pageInt)
	json.Unmarshal([]byte(pageSize), &pageSizeInt)

	offset := (pageInt - 1) * pageSizeInt

	err := query.Order("created_at desc").Offset(offset).Limit(pageSizeInt).Find(&logs).Error
	if err != nil {
		response.FailWithMessage("查询失败", c)
		return
	}

	result := map[string]interface{}{
		"list":      logs,
		"total":     total,
		"page":      pageInt,
		"page_size": pageSizeInt,
	}

	response.OkWithDetailed(result, "获取成功", c)
}

// convertToPluginConfig 转换数据库模型为插件配置
func (w *WafPluginApi) convertToPluginConfig(plugin *model.WafPluginConfig) *pluginconfig.PluginConfig {
	config := &pluginconfig.PluginConfig{
		ID:          plugin.PluginID,
		Name:        plugin.Name,
		Description: plugin.Description,
		Type:        plugin.Type,
		Version:     plugin.Version,
		Enabled:     plugin.Enabled == 1,
		BinaryPath:  plugin.BinaryPath,
		Priority:    plugin.Priority,
	}

	// 解析JSON字段
	if plugin.Groups != "" {
		json.Unmarshal([]byte(plugin.Groups), &config.Groups)
	}
	if plugin.Params != "" {
		json.Unmarshal([]byte(plugin.Params), &config.Params)
	}
	if plugin.InputSchema != "" {
		json.Unmarshal([]byte(plugin.InputSchema), &config.InputSchema)
	}
	if plugin.OutputSchema != "" {
		json.Unmarshal([]byte(plugin.OutputSchema), &config.OutputSchema)
	}

	return config
}
