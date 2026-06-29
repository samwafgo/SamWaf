package api

import (
	"SamWaf/global"
	"SamWaf/iplocation"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/utils"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

type WafIPLocationApi struct {
}

// ipdbStatusResponse 在 DBStatus 基础上追加文件存在信息
type ipdbStatusResponse struct {
	iplocation.DBStatus
	FileExists map[string]bool `json:"file_exists"`
}

// IPDBConfigResp IP 数据库配置项响应
type IPDBConfigResp struct {
	Ipv4Source string `json:"ipv4_source"`
	Ipv4Format string `json:"ipv4_format"`
	Ipv6Source string `json:"ipv6_source"`
	Ipv6Format string `json:"ipv6_format"`
}

// IPDBConfigReq IP 数据库配置项保存入参
type IPDBConfigReq struct {
	Ipv4Source string `json:"ipv4_source"`
	Ipv4Format string `json:"ipv4_format"`
	Ipv6Source string `json:"ipv6_source"`
	Ipv6Format string `json:"ipv6_format"`
}

// ---- 内部 helpers ----

// applyIPConfig 原子地更新单个 IP 配置项：① 写 DB → ② 同步 global
func applyIPConfig(item, value string) error {
	if err := wafSystemConfigService.ModifyByItemApi(request.WafSystemConfigEditByItemReq{
		Item:  item,
		Value: value,
	}); err != nil {
		return err
	}
	switch item {
	case "ip_v4_source":
		global.GCONFIG_IP_V4_SOURCE = value
	case "ip_v6_source":
		global.GCONFIG_IP_V6_SOURCE = value
	case "ip_v4_format":
		global.GCONFIG_IP_V4_FORMAT = value
	case "ip_v6_format":
		global.GCONFIG_IP_V6_FORMAT = value
	}
	return nil
}

// getConfigOrDefault 从 sys_config 读取配置项，空值返回默认值
func getConfigOrDefault(item, def string) string {
	bean := wafSystemConfigService.GetDetailByItemApi(request.WafSystemConfigDetailByItemReq{Item: item})
	if bean.Value == "" {
		return def
	}
	return bean.Value
}

// sourceFileExists 检查指定 ip 类型与 source 对应的物理文件是否存在
func sourceFileExists(ipType, source, dataDir string) bool {
	var fileName string
	switch source {
	case "ip2region":
		if ipType == "ipv4" {
			fileName = "ip2region.xdb"
		} else {
			fileName = "ip2region_v6.xdb"
		}
	case "geolite2":
		fileName = "GeoLite2-Country.mmdb"
	case "ipdb":
		fileName = "iplocation.ipdb"
	default:
		return false
	}
	_, err := os.Stat(filepath.Join(dataDir, fileName))
	return err == nil
}

// reloadManagerByCurrentConfig 根据 global 中当前的 source/format 重新加载 manager
// 所有 source 切换、配置变更、手动 reload 都应通过此函数集中处理。
// 实际加载逻辑收敛在 iplocation.Manager.ReloadFromConfig，与启动后置加载共用同一份实现。
func reloadManagerByCurrentConfig() error {
	if global.GIPLOCATION_MANAGER == nil {
		return nil
	}
	dataDir := filepath.Join(utils.GetCurrentDir(), "data")
	return global.GIPLOCATION_MANAGER.ReloadFromConfig(
		dataDir,
		global.GCONFIG_IP_V4_SOURCE, global.GCONFIG_IP_V6_SOURCE,
		global.GCONFIG_IP_V4_FORMAT, global.GCONFIG_IP_V6_FORMAT,
	)
}

// ---- API Handlers ----

// GetIPDBStatusApi 获取 IP 数据库状态
func (w *WafIPLocationApi) GetIPDBStatusApi(c *gin.Context) {
	if global.GIPLOCATION_MANAGER == nil {
		response.FailWithMessage("IP 数据库管理器未初始化", c)
		return
	}

	status := global.GIPLOCATION_MANAGER.GetStatus()

	dataDir := filepath.Join(utils.GetCurrentDir(), "data")

	// 获取 IPv4 文件创建时间
	var ipv4FilePath string
	switch status.IPv4Source {
	case "ip2region":
		ipv4FilePath = filepath.Join(dataDir, "ip2region.xdb")
	case "geolite2":
		ipv4FilePath = filepath.Join(dataDir, "GeoLite2-Country.mmdb")
	case "ipdb":
		ipv4FilePath = filepath.Join(dataDir, "iplocation.ipdb")
	}
	if ipv4FilePath != "" {
		if fileInfo, err := os.Stat(ipv4FilePath); err == nil {
			status.IPv4CreateTime = fileInfo.ModTime().Format("2006-01-02 15:04:05")
		}
	}

	// 获取 IPv6 文件创建时间
	var ipv6FilePath string
	switch status.IPv6Source {
	case "ip2region":
		ipv6FilePath = filepath.Join(dataDir, "ip2region_v6.xdb")
	case "geolite2":
		ipv6FilePath = filepath.Join(dataDir, "GeoLite2-Country.mmdb")
	case "ipdb":
		ipv6FilePath = filepath.Join(dataDir, "iplocation.ipdb")
	}
	if ipv6FilePath != "" {
		if fileInfo, err := os.Stat(ipv6FilePath); err == nil {
			status.IPv6CreateTime = fileInfo.ModTime().Format("2006-01-02 15:04:05")
		}
	}

	// 检查各数据库文件是否存在于磁盘
	checkFile := func(name string) bool {
		_, err := os.Stat(filepath.Join(dataDir, name))
		return err == nil
	}
	fileExists := map[string]bool{
		"ip2region_v4": checkFile("ip2region.xdb"),
		"ip2region_v6": checkFile("ip2region_v6.xdb"),
		"geolite2":     checkFile("GeoLite2-Country.mmdb"),
		"ipdb":         checkFile("iplocation.ipdb"),
	}

	response.OkWithDetailed(ipdbStatusResponse{
		DBStatus:   *status,
		FileExists: fileExists,
	}, "获取成功", c)
}

// GetIPDBConfigApi 一次性读取 IP 数据库的 source/format 配置项
func (w *WafIPLocationApi) GetIPDBConfigApi(c *gin.Context) {
	resp := IPDBConfigResp{
		Ipv4Source: getConfigOrDefault("ip_v4_source", "ip2region"),
		Ipv4Format: getConfigOrDefault("ip_v4_format", "legacy"),
		Ipv6Source: getConfigOrDefault("ip_v6_source", "geolite2"),
		Ipv6Format: getConfigOrDefault("ip_v6_format", "legacy"),
	}
	response.OkWithDetailed(resp, "获取成功", c)
}

// SaveIPDBConfigApi 保存 IP 数据库配置，原子更新 DB+global 并重载 manager
func (w *WafIPLocationApi) SaveIPDBConfigApi(c *gin.Context) {
	var req IPDBConfigReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("参数解析失败: "+err.Error(), c)
		return
	}

	// 合法值校验
	validV4 := map[string]bool{"ip2region": true, "ipdb": true}
	validV6 := map[string]bool{"ip2region": true, "geolite2": true, "ipdb": true}
	if !validV4[req.Ipv4Source] {
		response.FailWithMessage("IPv4 数据源非法: "+req.Ipv4Source, c)
		return
	}
	if !validV6[req.Ipv6Source] {
		response.FailWithMessage("IPv6 数据源非法: "+req.Ipv6Source, c)
		return
	}

	// 文件存在性兜底校验
	dataDir := filepath.Join(utils.GetCurrentDir(), "data")
	if !sourceFileExists("ipv4", req.Ipv4Source, dataDir) {
		response.FailWithMessage("IPv4 所选来源的数据库文件不存在，请先上传", c)
		return
	}
	if !sourceFileExists("ipv6", req.Ipv6Source, dataDir) {
		response.FailWithMessage("IPv6 所选来源的数据库文件不存在，请先上传", c)
		return
	}

	// 同步 DB + global
	if err := applyIPConfig("ip_v4_source", req.Ipv4Source); err != nil {
		response.FailWithMessage("保存 IPv4 数据源失败: "+err.Error(), c)
		return
	}
	if req.Ipv4Format != "" {
		if err := applyIPConfig("ip_v4_format", req.Ipv4Format); err != nil {
			response.FailWithMessage("保存 IPv4 字段格式失败: "+err.Error(), c)
			return
		}
	}
	if err := applyIPConfig("ip_v6_source", req.Ipv6Source); err != nil {
		response.FailWithMessage("保存 IPv6 数据源失败: "+err.Error(), c)
		return
	}
	if req.Ipv6Format != "" {
		if err := applyIPConfig("ip_v6_format", req.Ipv6Format); err != nil {
			response.FailWithMessage("保存 IPv6 字段格式失败: "+err.Error(), c)
			return
		}
	}

	// 按最新 source 重载 manager
	if err := reloadManagerByCurrentConfig(); err != nil {
		response.FailWithMessage("配置已保存但重载失败: "+err.Error(), c)
		return
	}

	response.OkWithMessage("配置已保存并生效", c)
}

// UploadIPDBFileApi 上传 IP 数据库文件
func (w *WafIPLocationApi) UploadIPDBFileApi(c *gin.Context) {
	ipType := c.PostForm("type")
	if ipType != "ipv4" && ipType != "ipv6" && ipType != "ipdb" {
		response.FailWithMessage("无效的类型参数，必须是 ipv4、ipv6 或 ipdb", c)
		return
	}

	file, err := c.FormFile("file")
	if err != nil {
		response.FailWithMessage("文件上传失败: "+err.Error(), c)
		return
	}

	ext := filepath.Ext(file.Filename)
	if ext != ".xdb" && ext != ".mmdb" && ext != ".ipdb" {
		response.FailWithMessage("不支持的文件类型，仅支持 .xdb、.mmdb 和 .ipdb 文件", c)
		return
	}
	if ext == ".ipdb" && ipType != "ipdb" {
		response.FailWithMessage(".ipdb 文件请使用 type=ipdb 上传", c)
		return
	}
	if ext != ".ipdb" && ipType == "ipdb" {
		response.FailWithMessage("type=ipdb 仅支持 .ipdb 文件", c)
		return
	}

	dataDir := filepath.Join(utils.GetCurrentDir(), "data")
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		if err = os.MkdirAll(dataDir, 0755); err != nil {
			response.FailWithMessage("创建数据目录失败: "+err.Error(), c)
			return
		}
	}

	// ipdb 双栈共用一个文件，独立处理
	if ext == ".ipdb" {
		finalPath := filepath.Join(dataDir, "iplocation.ipdb")
		tempPath := finalPath + ".tmp"

		if err = c.SaveUploadedFile(file, tempPath); err != nil {
			response.FailWithMessage("保存临时文件失败: "+err.Error(), c)
			return
		}

		if global.GIPLOCATION_MANAGER != nil {
			if err = global.GIPLOCATION_MANAGER.LoadIpdb(tempPath); err != nil {
				os.Remove(tempPath)
				response.FailWithMessage("加载 ipdb 数据库失败: "+err.Error(), c)
				return
			}
		}

		if err = os.Rename(tempPath, finalPath); err != nil {
			os.Remove(tempPath)
			response.FailWithMessage("替换文件失败: "+err.Error(), c)
			return
		}

		// 从最终路径重新加载，更新 manager 内部元数据
		if global.GIPLOCATION_MANAGER != nil {
			_ = global.GIPLOCATION_MANAGER.LoadIpdb(finalPath)
			global.GIPLOCATION_MANAGER.SetBothSourceIpdb()
			_ = applyIPConfig("ip_v4_source", "ipdb")
			_ = applyIPConfig("ip_v6_source", "ipdb")
		}

		response.OkWithMessage("ipdb 文件上传成功并已重新加载（IPv4+IPv6）", c)
		return
	}

	// xdb / mmdb 保存路径
	var finalPath string
	if ipType == "ipv4" {
		if ext == ".xdb" {
			finalPath = filepath.Join(dataDir, "ip2region.xdb")
		} else {
			finalPath = filepath.Join(dataDir, "GeoLite2-Country.mmdb")
		}
	} else {
		if ext == ".xdb" {
			finalPath = filepath.Join(dataDir, "ip2region_v6.xdb")
		} else {
			finalPath = filepath.Join(dataDir, "GeoLite2-Country.mmdb")
		}
	}

	tempPath := finalPath + ".tmp"
	if err = c.SaveUploadedFile(file, tempPath); err != nil {
		response.FailWithMessage("保存临时文件失败: "+err.Error(), c)
		return
	}

	fileData, err := ioutil.ReadFile(tempPath)
	if err != nil {
		os.Remove(tempPath)
		response.FailWithMessage("读取文件失败: "+err.Error(), c)
		return
	}

	if global.GIPLOCATION_MANAGER != nil {
		var reloadErr error
		var sourceItem, sourceValue string
		if ipType == "ipv4" {
			if ext == ".xdb" {
				reloadErr = global.GIPLOCATION_MANAGER.LoadV4Ip2Region(fileData, iplocation.DBFormat(global.GCONFIG_IP_V4_FORMAT))
				sourceItem, sourceValue = "ip_v4_source", "ip2region"
			} else {
				reloadErr = global.GIPLOCATION_MANAGER.LoadV4GeoLite2(fileData)
				sourceItem, sourceValue = "ip_v4_source", "geolite2"
			}
		} else {
			if ext == ".xdb" {
				reloadErr = global.GIPLOCATION_MANAGER.LoadV6Ip2Region(fileData, iplocation.DBFormat(global.GCONFIG_IP_V6_FORMAT))
				sourceItem, sourceValue = "ip_v6_source", "ip2region"
			} else {
				reloadErr = global.GIPLOCATION_MANAGER.LoadV6GeoLite2(fileData)
				sourceItem, sourceValue = "ip_v6_source", "geolite2"
			}
		}

		if reloadErr != nil {
			os.Remove(tempPath)
			response.FailWithMessage("加载数据库失败: "+reloadErr.Error(), c)
			return
		}

		_ = applyIPConfig(sourceItem, sourceValue)
	}

	if err = os.Rename(tempPath, finalPath); err != nil {
		os.Remove(tempPath)
		response.FailWithMessage("替换文件失败: "+err.Error(), c)
		return
	}

	response.OkWithMessage("文件上传成功并已重新加载", c)
}

// ReloadIPDBApi 重新加载 IP 数据库
func (w *WafIPLocationApi) ReloadIPDBApi(c *gin.Context) {
	if global.GIPLOCATION_MANAGER == nil {
		response.FailWithMessage("IP 数据库管理器未初始化", c)
		return
	}

	if err := reloadManagerByCurrentConfig(); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}

	response.OkWithMessage("数据库重新加载成功", c)
}

// TestIPLookupApi 测试 IP 查询
func (w *WafIPLocationApi) TestIPLookupApi(c *gin.Context) {
	var req struct {
		IP string `json:"ip" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("参数解析失败", c)
		return
	}

	if global.GIPLOCATION_MANAGER == nil {
		response.FailWithMessage("IP 数据库管理器未初始化", c)
		return
	}

	result := global.GIPLOCATION_MANAGER.Lookup(req.IP)

	// 识别 IP 类型 + 使用的数据源/格式
	ipType, usedSource, usedFormat := "未知", "", ""
	if parsed := net.ParseIP(req.IP); parsed != nil {
		if parsed.To4() != nil {
			ipType = "IPv4"
			usedSource = global.GCONFIG_IP_V4_SOURCE
			usedFormat = global.GCONFIG_IP_V4_FORMAT
		} else {
			ipType = "IPv6"
			usedSource = global.GCONFIG_IP_V6_SOURCE
			usedFormat = global.GCONFIG_IP_V6_FORMAT
		}
	}

	resp := map[string]interface{}{
		"ip":          req.IP,
		"ip_type":     ipType,
		"used_source": usedSource,
		"used_format": usedFormat, // 仅 ip2region 时有意义
		"country":     result.Country,
		"province":    result.Province,
		"city":        result.City,
		"isp":         result.ISP,
		"region":      result.Region,
		"district":    result.District,
		"raw":         fmt.Sprintf("%v", result.ToSlice()),
	}

	response.OkWithDetailed(resp, "查询成功", c)
}
