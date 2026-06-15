package api

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/utils"
	"SamWaf/wafai"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

type WafAIApi struct {
}

const (
	aiModelDir       = "ai_model"
	aiModelFile      = "current.swai"
	aiExportDir      = "ai_export"
	maxAIModelUpload = 64 * 1024 * 1024 // 模型包上传上限 64MB
	defaultExportMax = 200000           // 默认最多导出条数
)

// aiStatusResp AI 检测状态响应
type aiStatusResp struct {
	GlobalEnable   int64           `json:"global_enable"`   // 全局总开关
	Mode           string          `json:"mode"`            // observe / block
	ModelLoaded    bool            `json:"model_loaded"`    // 当前是否已加载模型
	FeatureVersion string          `json:"feature_version"` // 引擎特征版本
	Manifest       *wafai.Manifest `json:"manifest"`        // 当前模型元数据（未加载为 null）
}

// GetAIStatusApi 获取 AI 检测状态与当前模型信息
func (w *WafAIApi) GetAIStatusApi(c *gin.Context) {
	resp := aiStatusResp{
		GlobalEnable:   global.GCONFIG_AI_ENABLE,
		Mode:           global.GCONFIG_AI_MODE,
		FeatureVersion: wafai.FeatureVersion,
	}
	if global.GWAF_AI_DETECTOR != nil {
		if m, ok := global.GWAF_AI_DETECTOR.CurrentManifest(); ok {
			resp.ModelLoaded = true
			resp.Manifest = &m
		}
	}
	response.OkWithData(resp, c)
}

// UploadAIModelApi 上传 .swai 模型包：校验 -> 热加载 -> 持久化
func (w *WafAIApi) UploadAIModelApi(c *gin.Context) {
	if global.GWAF_AI_DETECTOR == nil {
		response.FailWithMessage("AI检测器未初始化", c)
		return
	}
	file, err := c.FormFile("file")
	if err != nil {
		response.FailWithMessage("文件上传失败: "+err.Error(), c)
		return
	}
	if strings.ToLower(filepath.Ext(file.Filename)) != ".swai" {
		response.FailWithMessage("不支持的文件类型，仅支持 .swai 模型包", c)
		return
	}
	if file.Size > maxAIModelUpload {
		response.FailWithMessage("模型包过大（上限 64MB）", c)
		return
	}

	src, err := file.Open()
	if err != nil {
		response.FailWithMessage("打开上传文件失败: "+err.Error(), c)
		return
	}
	defer src.Close()
	data, err := io.ReadAll(io.LimitReader(src, maxAIModelUpload+1))
	if err != nil {
		response.FailWithMessage("读取上传文件失败: "+err.Error(), c)
		return
	}
	if int64(len(data)) > maxAIModelUpload {
		response.FailWithMessage("模型包过大（上限 64MB）", c)
		return
	}

	// 先校验+热加载到内存（含特征版本/sha256/zip 安全校验），通过后再落盘
	manifest, err := global.GWAF_AI_DETECTOR.LoadFromBytes(data)
	if err != nil {
		response.FailWithMessage("模型校验失败: "+err.Error(), c)
		return
	}

	// 持久化到 data/ai_model/current.swai（原子替换），供下次启动加载
	dir := filepath.Join(utils.GetCurrentDir(), "data", aiModelDir)
	if err = os.MkdirAll(dir, 0750); err != nil {
		response.FailWithMessage("创建模型目录失败: "+err.Error(), c)
		return
	}
	finalPath := filepath.Join(dir, aiModelFile)
	tmpPath := finalPath + ".tmp"
	if err = os.WriteFile(tmpPath, data, 0640); err != nil {
		response.FailWithMessage("保存模型文件失败: "+err.Error(), c)
		return
	}
	if err = os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		response.FailWithMessage("替换模型文件失败: "+err.Error(), c)
		return
	}

	response.OkWithDetailed(manifest, "模型上传并加载成功", c)
}

// ReloadAIModelApi 从磁盘重新加载当前模型
func (w *WafAIApi) ReloadAIModelApi(c *gin.Context) {
	if global.GWAF_AI_DETECTOR == nil {
		response.FailWithMessage("AI检测器未初始化", c)
		return
	}
	path := filepath.Join(utils.GetCurrentDir(), "data", aiModelDir, aiModelFile)
	if _, err := os.Stat(path); err != nil {
		response.FailWithMessage("没有可加载的模型文件，请先上传", c)
		return
	}
	manifest, err := global.GWAF_AI_DETECTOR.LoadFromFile(path)
	if err != nil {
		response.FailWithMessage("模型加载失败: "+err.Error(), c)
		return
	}
	response.OkWithDetailed(manifest, "模型重新加载成功", c)
}

// UnloadAIModelApi 卸载当前模型（不删除磁盘文件）
func (w *WafAIApi) UnloadAIModelApi(c *gin.Context) {
	if global.GWAF_AI_DETECTOR != nil {
		global.GWAF_AI_DETECTOR.Unload()
	}
	response.OkWithMessage("模型已卸载", c)
}

// GetAIDashboardApi AI检测看板：按类别汇总 + 分数分布 + observe/block 趋势
func (w *WafAIApi) GetAIDashboardApi(c *gin.Context) {
	var req request.WafAIDashboardReq
	_ = c.ShouldBindJSON(&req)
	response.OkWithData(wafAIService.DashboardApi(req), c)
}

// MarkLabelApi 标记某条日志的训练标签修正（误报→正常 / 确认攻击 / 忽略）
func (w *WafAIApi) MarkLabelApi(c *gin.Context) {
	var req request.WafAILabelMarkReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("参数错误: "+err.Error(), c)
		return
	}
	if err := wafAILabelService.MarkApi(req); err != nil {
		response.FailWithMessage("标记失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("标记成功", c)
}

// UnmarkLabelApi 取消某条日志的标记
func (w *WafAIApi) UnmarkLabelApi(c *gin.Context) {
	var req request.WafAILabelUnmarkReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("参数错误: "+err.Error(), c)
		return
	}
	if err := wafAILabelService.UnmarkApi(req.ReqUuid); err != nil {
		response.FailWithMessage("取消标记失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("已取消标记", c)
}

// LabelByUuidsApi 按 req_uuid 批量查询标记状态（日志列表回显用）
func (w *WafAIApi) LabelByUuidsApi(c *gin.Context) {
	var req request.WafAILabelByUuidsReq
	_ = c.ShouldBindJSON(&req)
	response.OkWithData(wafAILabelService.GetMapByUuidsApi(req.ReqUuids), c)
}

// LabelListApi 标注工作台列表：AI 命中分页 + 标记状态过滤/回显
func (w *WafAIApi) LabelListApi(c *gin.Context) {
	var req request.WafAILabelListReq
	_ = c.ShouldBindJSON(&req)
	response.OkWithData(wafAILabelService.ListApi(req), c)
}

// BatchMarkLabelApi 批量标记训练标签（误报→正常 / 确认攻击 / 忽略）
func (w *WafAIApi) BatchMarkLabelApi(c *gin.Context) {
	var req request.WafAILabelBatchMarkReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("参数错误: "+err.Error(), c)
		return
	}
	n, err := wafAILabelService.BatchMarkApi(req)
	if err != nil {
		response.FailWithMessage(fmt.Sprintf("批量标记失败(已处理%d条): %s", n, err.Error()), c)
		return
	}
	response.OkWithMessage(fmt.Sprintf("已标记 %d 条", n), c)
}

// BatchUnmarkLabelApi 批量取消标记
func (w *WafAIApi) BatchUnmarkLabelApi(c *gin.Context) {
	var req request.WafAILabelBatchUnmarkReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("参数错误: "+err.Error(), c)
		return
	}
	n, err := wafAILabelService.BatchUnmarkApi(req.ReqUuids)
	if err != nil {
		response.FailWithMessage("批量取消标记失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage(fmt.Sprintf("已取消 %d 条标记", n), c)
}

// trainSample 导出的训练样本（字段名与 SamWafAI samwafai/data/sample.py 对齐）
type trainSample struct {
	Method     string `json:"method"`
	Path       string `json:"path"`
	Query      string `json:"query"`
	Body       string `json:"body"`
	UserAgent  string `json:"user_agent"`
	Label      int    `json:"label"`
	AttackType string `json:"attack_type"`
	Source     string `json:"source"`
}

// ExportTrainDataApi 导出脱敏训练数据为 JSONL，落到 data/ai_export/ 供本地训练
// aiExportRunning 导出任务并发保护：同一时刻只允许一个导出在跑
var aiExportRunning int32

func (w *WafAIApi) ExportTrainDataApi(c *gin.Context) {
	var req request.WafAIExportReq
	_ = c.ShouldBindJSON(&req)
	maxCount := req.MaxCount
	if maxCount <= 0 || maxCount > defaultExportMax {
		maxCount = defaultExportMax
	}

	if global.GWAF_LOCAL_LOG_DB == nil {
		response.FailWithMessage("日志库未初始化", c)
		return
	}

	// 导出是耗时操作（大表查询 + 逐行脱敏写盘），异步执行避免请求超时；
	// 完成/失败通过 OpResultMessageInfo 推送到管理端通知中心。
	if !atomic.CompareAndSwapInt32(&aiExportRunning, 0, 1) {
		response.FailWithMessage("已有导出任务正在进行，请等待完成", c)
		return
	}

	go func() {
		defer atomic.StoreInt32(&aiExportRunning, 0)
		outPath, nAttack, nNormal, nDrop, _, err := runAIExport(req, maxCount)
		serverName := global.GWAF_CUSTOM_SERVER_NAME
		if err != nil {
			global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.OpResultMessageInfo{
				BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "AI训练数据导出", Server: serverName},
				Msg:             "AI训练数据导出失败：" + err.Error(),
				Success:         "false",
			})
			return
		}
		global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.OpResultMessageInfo{
			BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "AI训练数据导出", Server: serverName},
			Msg: fmt.Sprintf("AI训练数据导出完毕：%s（写入%d条，攻击%d/正常%d，已忽略%d）",
				outPath, nAttack+nNormal, nAttack, nNormal, nDrop),
			Success: "true",
		})
	}()

	response.OkWithMessage("导出任务已开始，完成后会在通知中心提示，文件生成在服务器 data/ai_export/ 目录", c)
}

// runAIExport 实际执行训练数据导出，返回文件路径与各类计数。
func runAIExport(req request.WafAIExportReq, maxCount int) (outPath string, nAttack, nNormal, nDrop, total int, err error) {
	query := global.GWAF_LOCAL_LOG_DB.Model(&innerbean.WebLog{}).
		Select("REQ_UUID", "METHOD", "URL", "RawQuery", "BODY", "POST_FORM", "USER_AGENT", "ACTION", "RULE", "LogOnlyMode")
	if req.Days > 0 {
		cutoff := time.Now().AddDate(0, 0, -req.Days).Format("2006-01-02 15:04:05")
		query = query.Where("create_time >= ?", cutoff)
	}

	var rows []innerbean.WebLog
	if err = query.Order("unix_add_time desc").Limit(maxCount).Find(&rows).Error; err != nil {
		return "", 0, 0, 0, 0, fmt.Errorf("查询日志失败: %w", err)
	}
	total = len(rows)

	dir := filepath.Join(utils.GetCurrentDir(), "data", aiExportDir)
	if err = os.MkdirAll(dir, 0750); err != nil {
		return "", 0, 0, 0, total, fmt.Errorf("创建导出目录失败: %w", err)
	}
	outPath = filepath.Join(dir, fmt.Sprintf("train_%s.jsonl", time.Now().Format("20060102_150405")))
	fh, ferr := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if ferr != nil {
		return "", 0, 0, 0, total, fmt.Errorf("创建导出文件失败: %w", ferr)
	}
	defer fh.Close()
	enc := json.NewEncoder(fh)

	// 一次性加载人工标记（含请求快照），人工修正优先于规则弱标签
	marks := wafAILabelService.GetAllFull()

	// 1) 过滤窗口内的日志：仅处理"未人工标记"的（已标记的统一在第2步从快照产出，
	//    确保人工修正不会被时间/条数条件漏掉）
	for i := range rows {
		r := &rows[i]
		if _, marked := marks[r.REQ_UUID]; marked {
			continue
		}
		verdict, at := wafai.WeakLabel(r.ACTION, r.RULE, r.LogOnlyMode)
		if verdict == wafai.VerdictDrop {
			nDrop++
			continue
		}
		label := 0
		attackType := ""
		if verdict == wafai.VerdictAttack {
			// 仅信任高置信检测器(libinjection/OWASP)的攻击标签；
			// 低置信(scan/rce/traversal 等)未经人工确认则丢弃，避免规则误报污染训练
			if !wafai.IsHighConfidenceAttackType(at) {
				nDrop++
				continue
			}
			label = 1
			attackType = at
		}
		path, rawQuery := splitURL(r.URL, r.RawQuery)
		body := r.BODY
		if body == "" {
			body = r.POST_FORM
		}
		if label == 1 {
			nAttack++
		} else {
			nNormal++
		}
		s := trainSample{
			Method:     strings.ToUpper(r.METHOD),
			Path:       path,
			Query:      desensitizeForExport(rawQuery),
			Body:       desensitizeForExport(body),
			UserAgent:  r.USER_AGENT,
			Label:      label,
			AttackType: attackType,
			Source:     "samwaf_log",
		}
		if err = enc.Encode(&s); err != nil {
			return outPath, nAttack, nNormal, nDrop, total, fmt.Errorf("写入导出文件失败: %w", err)
		}
	}

	// 2) 全部人工标记从快照产出，不受时间/条数条件限制（连原始日志被清理也能产出）
	for _, m := range marks {
		if m.Mark == "ignore" {
			nDrop++
			continue
		}
		label := 0
		if m.Mark == "attack" {
			label = 1
		}
		path, rawQuery := splitURL(m.URL, m.RAW_QUERY)
		if label == 1 {
			nAttack++
		} else {
			nNormal++
		}
		s := trainSample{
			Method:     strings.ToUpper(m.METHOD),
			Path:       path,
			Query:      desensitizeForExport(rawQuery),
			Body:       desensitizeForExport(m.BODY),
			UserAgent:  m.USER_AGENT,
			Label:      label,
			AttackType: m.AttackType,
			Source:     "manual",
		}
		if err = enc.Encode(&s); err != nil {
			return outPath, nAttack, nNormal, nDrop, total, fmt.Errorf("写入导出文件失败: %w", err)
		}
	}
	return outPath, nAttack, nNormal, nDrop, total, nil
}

// splitURL 将 URL 拆为 path 与 query；优先用已有的 RawQuery
func splitURL(rawURL, rawQuery string) (string, string) {
	path := rawURL
	if rawQuery == "" {
		if u, err := url.Parse(rawURL); err == nil {
			path = u.Path
			rawQuery = u.RawQuery
		}
	} else if idx := strings.IndexByte(rawURL, '?'); idx >= 0 {
		path = rawURL[:idx]
	}
	if path == "" {
		path = "/"
	}
	return path, rawQuery
}

// desensitizeForExport 导出前再做一次脱敏（复用 godlp 引擎），避免敏感参数值随训练数据外泄
func desensitizeForExport(s string) string {
	if s == "" || global.GWAF_DLP == nil {
		return s
	}
	return utils.DeSenText(s)
}
