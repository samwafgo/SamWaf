package wafwebcache

import (
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/utils"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// LoadWebDataFormCache  从缓存里面拿数据
func LoadWebDataFormCache(w http.ResponseWriter, r *http.Request, hostSafe *wafenginmodel.HostSafe, cacheConfig model.CacheConfig, weblog *innerbean.WebLog) *http.Response {
	bodyHashKey := ""
	if weblog.SrcByteBody != nil && len(weblog.SrcByteBody) > 0 {
		bodyHash := sha256.Sum256(weblog.SrcByteBody)
		bodyHashKey = hex.EncodeToString(bodyHash[:])
		//重新赋值给weblog
		weblog.BodyHash = bodyHashKey
	}
	requestMethod := strings.ToLower(r.Method)
	requestURI := r.RequestURI

	zlog.Debug(fmt.Sprintf("缓存键组成部分 (加载) - 方法: %s, URI: %s", requestMethod, requestURI))

	key := utils.Md5String(requestMethod + requestURI)
	if requestMethod == "post" || requestMethod == "put" {
		zlog.Debug(fmt.Sprintf("缓存键组成部分 (加载) - BodyHash: %s (用于POST/PUT请求)", bodyHashKey))
		key = utils.Md5String(requestMethod + requestURI + bodyHashKey)
	}
	zlog.Debug(fmt.Sprintf("尝试从缓存加载数据 URL: %s, 缓存键: %s, 主机代码: %s, 缓存位置: %s",
		requestURI, key, hostSafe.Host.Code, cacheConfig.CacheLocation))

	//规则匹配查询
	_, err2 := checkCacheRule(hostSafe, cacheConfig, r)
	if err2 != nil {
		return nil
	}

	var data []byte = nil
	if cacheConfig.CacheLocation == "memory" || cacheConfig.CacheLocation == "all" {
		zlog.Debug(fmt.Sprintf("尝试从内存缓存加载 主机代码: %s, 缓存键: %s", hostSafe.Host.Code, key))
		memoryData := loadFormMemory(hostSafe.Host.Code, key)
		if memoryData == nil {
			zlog.Debug(fmt.Sprintf("内存缓存未命中 主机代码: %s, 缓存键: %s", hostSafe.Host.Code, key))
		} else {
			zlog.Debug(fmt.Sprintf("内存缓存命中 主机代码: %s, 缓存键: %s, 数据大小: %d",
				hostSafe.Host.Code, key, len(memoryData)))
			data = memoryData
		}
	}

	if data == nil && (cacheConfig.CacheLocation == "file" || cacheConfig.CacheLocation == "all") {
		zlog.Debug(fmt.Sprintf("尝试从文件缓存加载 主机代码: %s, 缓存键: %s, 缓存目录: %s",
			hostSafe.Host.Code, key, cacheConfig.CacheDir))
		fileData := loadFormFile(hostSafe.Host.Code, key, cacheConfig.CacheDir)
		if fileData == nil {
			zlog.Debug(fmt.Sprintf("文件缓存未命中 主机代码: %s, 缓存键: %s", hostSafe.Host.Code, key))
		} else {
			zlog.Debug(fmt.Sprintf("文件缓存命中 主机代码: %s, 缓存键: %s, 数据大小: %d",
				hostSafe.Host.Code, key, len(fileData)))
			data = fileData
		}
	}

	if data == nil {
		zlog.Debug(fmt.Sprintf("缓存完全未命中 URL: %s, 缓存键: %s", r.RequestURI, key))
		return nil
	}

	buf := bufio.NewReader(bytes.NewReader(data))
	resp, err := http.ReadResponse(buf, nil)
	if err != nil {
		zlog.Error(fmt.Sprintf("解析缓存响应失败 URL: %s, 缓存键: %s, 错误: %v", r.RequestURI, key, err))
		return nil
	}

	zlog.Debug(fmt.Sprintf("成功从缓存加载响应 URL: %s, 缓存键: %s, 状态码: %d, 响应头数量: %d",
		r.RequestURI, key, resp.StatusCode, len(resp.Header)))
	return resp
}

// StoreWebDataCache 缓存web数据到cache里面
func StoreWebDataCache(resp *http.Response, hostSafe *wafenginmodel.HostSafe, cacheConfig model.CacheConfig, weblog *innerbean.WebLog) {
	// 检查HTTP响应状态码，只缓存2xx的响应
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		zlog.Debug(fmt.Sprintf("响应状态码 %d 不符合缓存条件 (2xx)，不进行缓存 URL: %s",
			resp.StatusCode, resp.Request.RequestURI))
		return
	}

	requestMethod := strings.ToLower(resp.Request.Method)
	requestURI := resp.Request.RequestURI
	zlog.Debug(fmt.Sprintf("缓存键组成部分 - 方法: %s, URI: %s", requestMethod, requestURI))
	key := utils.Md5String(requestMethod + requestURI)
	if requestMethod == "post" || requestMethod == "put" {
		zlog.Debug(fmt.Sprintf("缓存键组成部分 - BodyHash: %s (用于POST/PUT请求)", weblog.BodyHash))
		key = utils.Md5String(requestMethod + requestURI + weblog.BodyHash)
	}
	zlog.Debug(fmt.Sprintf("尝试存储响应到缓存 URL: %s, 缓存键: %s, 主机代码: %s, 缓存位置: %s",
		requestURI, key, hostSafe.Host.Code, cacheConfig.CacheLocation))

	//规则匹配查询 获取缓存时间
	timeout, err2 := checkCacheRule(hostSafe, cacheConfig, resp.Request)
	if err2 != nil {
		return
	}

	data, err := httputil.DumpResponse(resp, true)
	if err != nil {
		zlog.Error(fmt.Sprintf("序列化响应失败 URL: %s, 错误: %v", requestURI, err))
		return
	}

	zlog.Debug(fmt.Sprintf("响应序列化成功 URL: %s, 数据大小: %d", requestURI, len(data)))

	if cacheConfig.CacheLocation == "memory" || cacheConfig.CacheLocation == "all" {
		zlog.Debug(fmt.Sprintf("存储到内存缓存 主机代码: %s, 缓存键: %s, 超时时间(秒): %d",
			hostSafe.Host.Code, key, timeout))
		storeMemory(hostSafe.Host.Code, key, data, timeout, cacheConfig.MaxMemorySizeMB)
	}

	if cacheConfig.CacheLocation == "file" || cacheConfig.CacheLocation == "all" {
		zlog.Debug(fmt.Sprintf("存储到文件缓存 主机代码: %s, 缓存键: %s, 缓存目录: %s, 超时时间(秒): %d",
			hostSafe.Host.Code, key, cacheConfig.CacheDir, timeout))
		storeFile(hostSafe.Host.Code, key, data, cacheConfig.CacheDir, timeout, cacheConfig.MaxFileSizeMB)
	}

	zlog.Debug(fmt.Sprintf("响应缓存完成 URL: %s, 缓存键: %s", resp.Request.RequestURI, key))
}

func loadFormMemory(hostCode string, key string) []byte {
	cacheKey := enums.CACHE_WEBFILE + hostCode + key
	zlog.Debug(fmt.Sprintf("检查内存缓存键 缓存键: %s", cacheKey))

	isKeyExist := global.GCACHE_WAFCACHE.IsKeyExist(cacheKey)
	if isKeyExist {
		zlog.Debug(fmt.Sprintf("内存缓存键存在 缓存键: %s", cacheKey))
		data, err := global.GCACHE_WAFCACHE.GetBytes(cacheKey)
		if err == nil {
			zlog.Debug(fmt.Sprintf("成功获取内存缓存数据 缓存键: %s, 数据大小: %d", cacheKey, len(data)))
			return data
		}
		zlog.Error(fmt.Sprintf("获取内存缓存数据失败 缓存键: %s, 错误: %v", cacheKey, err))
	} else {
		zlog.Debug(fmt.Sprintf("内存缓存键不存在 缓存键: %s", cacheKey))
	}
	return nil
}

func loadFormFile(hostCode string, key string, path string) []byte {
	safePath := filepath.Join(path, hostCode)

	// 获取目录中所有可能的缓存文件
	pattern := filepath.Join(safePath, key+".*.cache")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		zlog.Debug(fmt.Sprintf("文件缓存不存在 匹配模式: %s, 错误: %v", pattern, err))
		return nil
	}

	// 当前时间戳
	now := time.Now().Unix()

	// 查找有效的缓存文件（未过期的）
	var validFile string
	var latestExpire int64

	for _, match := range matches {
		// 从文件名中提取过期时间戳
		base := filepath.Base(match)
		parts := strings.Split(base, ".")
		if len(parts) < 3 {
			continue
		}

		expireStr := parts[len(parts)-2]
		expire, err := strconv.ParseInt(expireStr, 10, 64)
		if err != nil {
			continue
		}

		// 检查是否过期
		if expire > now {
			// 如果有多个有效文件，选择过期时间最晚的
			if expire > latestExpire {
				validFile = match
				latestExpire = expire
			}
		} else {
			// 文件已过期，可以选择删除
			zlog.Debug(fmt.Sprintf("缓存文件已过期，准备删除: %s", match))
			os.Remove(match)
		}
	}

	if validFile == "" {
		zlog.Debug(fmt.Sprintf("没有找到有效的缓存文件 键: %s", key))
		return nil
	}

	zlog.Debug(fmt.Sprintf("找到有效的缓存文件: %s, 过期时间戳: %d", validFile, latestExpire))

	data, err := ioutil.ReadFile(validFile)
	if err != nil {
		zlog.Error(fmt.Sprintf("读取文件缓存失败 文件路径: %s, 错误: %v", validFile, err))
		return nil
	}

	zlog.Debug(fmt.Sprintf("成功读取文件缓存 文件路径: %s, 数据大小: %d", validFile, len(data)))
	return data
}

func storeMemory(hostCode string, key string, data []byte, timeout int, maxSize float64) {
	cacheKey := enums.CACHE_WEBFILE + hostCode + key
	zlog.Debug(fmt.Sprintf("存储到内存缓存 缓存键: %s, 数据大小: %d", cacheKey, len(data)))

	// 检查内存大小限制
	dataSizeMB := float64(len(data)) / (1024 * 1024)
	if maxSize > 0 && dataSizeMB > maxSize {
		zlog.Warn(fmt.Sprintf("内存缓存大小超过限制 缓存键: %s, 数据大小: %.2fMB, 最大限制: %.2fMB",
			cacheKey, dataSizeMB, maxSize))
		return
	}

	if timeout > 0 {
		zlog.Debug(fmt.Sprintf("设置内存缓存带超时 缓存键: %s, 超时时间(秒): %d", cacheKey, timeout))
		global.GCACHE_WAFCACHE.SetWithTTlRenewTime(cacheKey, data, time.Duration(timeout)*time.Second)
	} else {
		zlog.Debug(fmt.Sprintf("设置内存缓存长期有效 缓存键: %s", cacheKey))
		global.GCACHE_WAFCACHE.SetWithTTlRenewTime(cacheKey, data, time.Duration(87600)*time.Hour)
	}
}

func storeFile(hostCode string, key string, data []byte, path string, timeout int, maxSize float64) {
	safePath := filepath.Join(path, hostCode)
	zlog.Debug(fmt.Sprintf("准备存储文件缓存 目录路径: %s, 缓存键: %s", safePath, key))

	// 确保缓存目录存在
	if _, err := os.Stat(safePath); os.IsNotExist(err) {
		zlog.Debug(fmt.Sprintf("缓存目录不存在，创建目录 目录路径: %s", safePath))
		err := os.MkdirAll(safePath, 0755)
		if err != nil {
			zlog.Error(fmt.Sprintf("创建缓存目录失败 目录路径: %s, 错误: %v", safePath, err))
			return
		}
	}

	// 计算过期时间戳
	var expireTimestamp int64
	if timeout > 0 {
		expireTimestamp = time.Now().Unix() + int64(timeout)
	} else {
		// 如果没有设置超时，使用一个很大的值（10年）
		expireTimestamp = time.Now().Unix() + 315360000
	}

	// 文件名中包含过期时间戳
	filename := filepath.Join(safePath, fmt.Sprintf("%s.%d.cache", key, expireTimestamp))
	zlog.Debug(fmt.Sprintf("写入文件缓存 文件路径: %s, 数据大小: %d, 过期时间戳: %d", filename, len(data), expireTimestamp))

	// 检查文件大小限制
	dataSizeMB := float64(len(data)) / (1024 * 1024)
	if maxSize > 0 && dataSizeMB > maxSize {
		zlog.Warn(fmt.Sprintf("文件缓存大小超过限制 文件路径: %s, 数据大小: %.2fMB, 最大限制: %.2fMB",
			filename, dataSizeMB, maxSize))
		return
	}

	err := ioutil.WriteFile(filename, data, 0644)
	if err != nil {
		zlog.Error(fmt.Sprintf("写入文件缓存失败 文件路径: %s, 错误: %v", filename, err))
		return
	}

	zlog.Debug(fmt.Sprintf("文件缓存写入成功 文件路径: %s", filename))
}

func checkCacheRule(hostSafe *wafenginmodel.HostSafe, cacheConfig model.CacheConfig, r *http.Request) (int, error) {
	//规则匹配查询
	if hostSafe.CacheRule == nil || len(hostSafe.CacheRule) == 0 {
		return 0, fmt.Errorf("没有配置缓存规则")
	}

	requestURI := r.URL.RequestURI()
	requestMethod := r.Method

	// 按优先级排序规则（优先级数字越大越优先）
	sort.Slice(hostSafe.CacheRule, func(i, j int) bool {
		return hostSafe.CacheRule[i].Priority > hostSafe.CacheRule[j].Priority
	})

	pureRequestUrl := r.URL.Path
	// 循环检查每个规则
	for _, rule := range hostSafe.CacheRule {
		finalUrl := requestURI
		if rule.ParamType == 1 {
			finalUrl = pureRequestUrl
		}

		// 检查请求方法是否匹配
		if !checkRequestMethod(requestMethod, rule.RequestMethod) {
			continue
		}

		// 根据规则类型进行匹配
		matched := false
		switch rule.RuleType {
		case 1: // 后缀匹配
			matched = checkSuffixMatch(finalUrl, rule.RuleContent)
		case 2: // 指定目录
			matched = checkDirectoryMatch(finalUrl, rule.RuleContent)
		case 3: // 指定文件
			matched = checkExactFileMatch(finalUrl, rule.RuleContent)
		}

		if matched {
			zlog.Debug(fmt.Sprintf("缓存规则匹配成功: %s, 缓存时间: %d秒", rule.RuleName, rule.CacheTime))
			return rule.CacheTime, nil
		}
	}

	// 没有匹配的规则
	return 0, fmt.Errorf("没有匹配的缓存规则")
}

// 检查请求方法是否匹配
func checkRequestMethod(requestMethod, ruleMethods string) bool {
	if ruleMethods == "" {
		return true // 空字符串表示匹配所有方法
	}

	methods := strings.Split(ruleMethods, ";")
	for _, method := range methods {
		if strings.TrimSpace(method) == requestMethod {
			return true
		}
	}
	return false
}

// 检查后缀匹配
func checkSuffixMatch(path, suffixes string) bool {
	if suffixes == "" {
		return false
	}

	suffixList := strings.Split(suffixes, ";")
	for _, suffix := range suffixList {
		suffix = strings.TrimSpace(suffix)
		if suffix != "" && strings.HasSuffix(strings.ToLower(path), strings.ToLower(suffix)) {
			return true
		}
	}
	return false
}

// 检查目录匹配
func checkDirectoryMatch(path, directories string) bool {
	if directories == "" {
		return false
	}

	dirList := strings.Split(directories, ";")
	for _, dir := range dirList {
		dir = strings.TrimSpace(dir)
		if dir != "" && strings.HasPrefix(strings.ToLower(path), strings.ToLower(dir)) {
			return true
		}
	}
	return false
}

// 检查精确文件匹配
func checkExactFileMatch(path, files string) bool {
	if files == "" {
		return false
	}

	fileList := strings.Split(files, ";")
	for _, file := range fileList {
		file = strings.TrimSpace(file)
		if file != "" && strings.ToLower(path) == strings.ToLower(file) {
			return true
		}
	}
	return false
}

// CleanExpiredCache 清理过期的缓存文件
func CleanExpiredCache(cacheDir string) {
	zlog.Debug(fmt.Sprintf("开始清理过期缓存文件 目录: %s", cacheDir))

	// 获取当前时间戳
	now := time.Now().Unix()

	// 遍历缓存目录
	err := filepath.Walk(cacheDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 只处理文件
		if !info.IsDir() {
			// 检查是否是缓存文件
			if strings.HasSuffix(path, ".cache") {
				// 从文件名中提取过期时间戳
				base := filepath.Base(path)
				parts := strings.Split(base, ".")
				if len(parts) >= 3 {
					expireStr := parts[len(parts)-2]
					expire, err := strconv.ParseInt(expireStr, 10, 64)
					if err == nil && expire <= now {
						// 文件已过期，删除
						zlog.Debug(fmt.Sprintf("删除过期缓存文件: %s", path))
						os.Remove(path)
					}
				}
			}
		}
		return nil
	})

	if err != nil {
		zlog.Error(fmt.Sprintf("清理过期缓存文件失败: %v", err))
	} else {
		zlog.Debug(fmt.Sprintf("清理过期缓存文件完成"))
	}
}
