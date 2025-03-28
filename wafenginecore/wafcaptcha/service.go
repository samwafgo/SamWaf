package wafcaptcha

import (
	"SamWaf/cache"
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/utils"
	"encoding/json"
	"fmt"
	"github.com/golang/freetype/truetype"
	uuid "github.com/satori/go.uuid"
	"github.com/wenlng/go-captcha-assets/bindata/chars"
	"github.com/wenlng/go-captcha-assets/resources/fonts/fzshengsksjw"
	"github.com/wenlng/go-captcha-assets/resources/images"
	"github.com/wenlng/go-captcha/v2/base/option"
	"github.com/wenlng/go-captcha/v2/click"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

var (
	captchaService *CaptchaService
	once           sync.Once
)

// CaptchaService 验证码服务结构体
type CaptchaService struct {
	cache *cache.WafCache
	//text
	textCapt      click.Captcha
	lightTextCapt click.Captcha
}

// InitCaptchaService 初始化验证码服务，传入缓存引用
func InitCaptchaService(cache *cache.WafCache) {
	once.Do(func() {
		captchaService = &CaptchaService{
			cache: cache,
		}
		captchaService.InitTextCapt()
	})
}
func (s *CaptchaService) InitTextCapt() {
	builder := click.NewBuilder(
		click.WithRangeLen(option.RangeVal{Min: 4, Max: 6}),
		click.WithRangeVerifyLen(option.RangeVal{Min: 2, Max: 4}),
		//click.WithRangeLen(option.RangeVal{Min: 2, Max: 4}),
		//click.WithDisabledRangeVerifyLen(true),
		click.WithRangeThumbColors([]string{
			"#1f55c4",
			"#780592",
			"#2f6b00",
			"#910000",
			"#864401",
			"#675901",
			"#016e5c",
		}),
		click.WithRangeColors([]string{
			"#fde98e",
			"#60c1ff",
			"#fcb08e",
			"#fb88ff",
			"#b4fed4",
			"#cbfaa9",
			"#78d6f8",
		}),
	)

	// fonts
	fonts, err := fzshengsksjw.GetFont()
	if err != nil {
		log.Fatalln(err)
	}

	// background images
	imgs, err := images.GetImages()
	if err != nil {
		log.Fatalln(err)
	}

	// thumb images
	//thumbImages, err := thumbs.GetThumbs()
	//if err != nil {
	//	log.Fatalln(err)
	//}

	// set resources
	builder.SetResources(
		click.WithChars(chars.GetChineseChars()),
		//click.WithChars([]string{
		//	"1A",
		//	"5E",
		//	"3d",
		//	"0p",
		//	"78",
		//	"DL",
		//	"CB",
		//	"9M",
		//}),
		//click.WithChars(chars.GetAlphaChars()),
		click.WithFonts([]*truetype.Font{fonts}),
		click.WithBackgrounds(imgs),
		//click.WithThumbBackgrounds(thumbImages),
	)
	s.textCapt = builder.Make()

	// ============================

	builder.Clear()
	builder.SetOptions(
		click.WithRangeLen(option.RangeVal{Min: 4, Max: 6}),
		click.WithRangeVerifyLen(option.RangeVal{Min: 2, Max: 4}),
		click.WithRangeThumbColors([]string{
			"#4a85fb",
			"#d93ffb",
			"#56be01",
			"#ee2b2b",
			"#cd6904",
			"#b49b03",
			"#01ad90",
		}),
	)
	builder.SetResources(
		click.WithChars(chars.GetChineseChars()),
		click.WithFonts([]*truetype.Font{fonts}),
		click.WithBackgrounds(imgs),
	)
	s.lightTextCapt = builder.Make()
}

// GetService 获取验证码服务实例
func GetService() *CaptchaService {
	if captchaService == nil {
		zlog.Warn("验证码服务未初始化，请先调用 InitCaptchaService")
		// 返回一个空服务，避免空指针异常
		return &CaptchaService{}
	}
	return captchaService
}

// HandleCaptchaRequest 处理验证码请求
func (s *CaptchaService) HandleCaptchaRequest(w http.ResponseWriter, r *http.Request, expireTime int, weblog innerbean.WebLog) {
	// 从路径中提取验证码相关部分
	path := r.URL.Path
	// 记录访问日志
	zlog.Debug("验证码请求", zap.String("path", path), zap.String("method", r.Method), zap.String("remote_addr", r.RemoteAddr))

	if strings.HasPrefix(path, "/samwaf_captcha/click_basic") {
		s.GetClickBasicCaptData(w, r)
	} else if strings.HasPrefix(path, "/samwaf_captcha/verify") {
		// 根据请求参数确定验证码类型
		captchaType := r.URL.Query().Get("type")
		s.VerifyCaptcha(w, r, captchaType, expireTime, weblog)
	} else if strings.HasPrefix(path, "/samwaf_captcha/") {
		cleanPath := strings.TrimPrefix(path, "/samwaf_captcha/")
		s.ServeStaticFile(w, r, cleanPath)
	} else {
		// 记录日志信息
		weblog.ACTION = "禁止"
		weblog.RULE = "显示图形验证码"
		global.GQEQUE_LOG_DB.Enqueue(weblog)
		// 默认显示验证码选择页面
		s.ShowCaptchaHomePage(w, r)
	}
}

// ServeStaticFile 提供静态文件服务
func (s *CaptchaService) ServeStaticFile(w http.ResponseWriter, r *http.Request, filePath string) {
	// 安全检查：防止路径遍历攻击
	if containsPathTraversal(filePath) {
		zlog.Warn("检测到路径遍历尝试", zap.String("path", filePath), zap.String("remote_addr", r.RemoteAddr))
		http.Error(w, "403 Forbidden", http.StatusForbidden)
		return
	}

	// 规范化文件路径，移除所有 ".." 和多余的斜杠
	cleanPath := path.Clean(filePath)

	// 确保路径不以 "/" 或 "\" 开头，防止访问根目录
	if strings.HasPrefix(cleanPath, "/") || strings.HasPrefix(cleanPath, "\\") {
		cleanPath = cleanPath[1:]
	}

	// 根据文件扩展名设置Content-Type
	if strings.HasSuffix(cleanPath, ".css") {
		w.Header().Set("Content-Type", "text/css")
	} else if strings.HasSuffix(cleanPath, ".js") {
		w.Header().Set("Content-Type", "application/javascript")
	} else if strings.HasSuffix(cleanPath, ".html") {
		w.Header().Set("Content-Type", "text/html")
	} else if strings.HasSuffix(cleanPath, ".png") {
		w.Header().Set("Content-Type", "image/png")
	} else if strings.HasSuffix(cleanPath, ".jpg") || strings.HasSuffix(cleanPath, ".jpeg") {
		w.Header().Set("Content-Type", "image/jpeg")
	}

	// 构建安全的完整路径
	basePath := utils.GetCurrentDir() + "/data/captcha/"
	fullPath := filepath.Join(basePath, cleanPath)

	// 再次验证路径是否在允许的目录内
	absBasePath, _ := filepath.Abs(basePath)
	absFullPath, _ := filepath.Abs(fullPath)

	if !strings.HasPrefix(absFullPath, absBasePath) {
		zlog.Warn("检测到目录遍历尝试", zap.String("path", filePath), zap.String("fullPath", fullPath), zap.String("remote_addr", r.RemoteAddr))
		http.Error(w, "403 Forbidden", http.StatusForbidden)
		return
	}

	// 检查文件是否存在
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		http.NotFound(w, r)
		return
	}

	// 提供文件服务
	http.ServeFile(w, r, fullPath)
}

// containsPathTraversal 检查路径中是否包含路径遍历尝试
func containsPathTraversal(filePath string) bool {
	// 检查常见的路径遍历模式
	return strings.Contains(filePath, "../") ||
		strings.Contains(filePath, "..\\") ||
		strings.Contains(filePath, "%2e%2e%2f") || // ../
		strings.Contains(filePath, "%2e%2e/") || // ../
		strings.Contains(filePath, "..%2f") || // ../
		strings.Contains(filePath, "%2e%2e%5c") || // ..\
		strings.Contains(filePath, "..%5c") || // ..\
		strings.Contains(filePath, "\\\\") || // 双反斜杠
		strings.Contains(filePath, "//") // 双正斜杠
}

// GetClickBasicCaptData 获取基础点击验证码数据
func (s *CaptchaService) GetClickBasicCaptData(w http.ResponseWriter, r *http.Request) {
	var capt click.Captcha

	// 首先检查请求参数中是否指定了语言
	userLang := r.URL.Query().Get("lang")

	// 如果没有指定语言，则检测浏览器语言
	isChineseUser := false
	if userLang != "" {
		// 优先使用用户选择的语言
		isChineseUser = userLang == "zh"
		zlog.Debug("使用用户选择的语言", zap.String("language", userLang), zap.Bool("isChineseUser", isChineseUser))
	} else {
		// 否则使用浏览器语言
		acceptLanguage := r.Header.Get("Accept-Language")
		isChineseUser = strings.Contains(strings.ToLower(acceptLanguage), "zh")
		zlog.Debug("使用浏览器语言", zap.String("acceptLanguage", acceptLanguage), zap.Bool("isChineseUser", isChineseUser))
	}

	// 根据用户语言和请求类型选择验证码
	if r.URL.Query().Get("type") == "light" {
		// 使用已经初始化好的lightTextCapt
		capt = s.lightTextCapt
	} else {
		// 根据语言动态生成验证码
		builder := click.NewBuilder(
			click.WithRangeLen(option.RangeVal{Min: 4, Max: 6}),
			click.WithRangeVerifyLen(option.RangeVal{Min: 2, Max: 4}),
			click.WithRangeThumbColors([]string{
				"#1f55c4", "#780592", "#2f6b00", "#910000",
				"#864401", "#675901", "#016e5c",
			}),
			click.WithRangeColors([]string{
				"#fde98e", "#60c1ff", "#fcb08e", "#fb88ff",
				"#b4fed4", "#cbfaa9", "#78d6f8",
			}),
		)

		// 获取字体和背景资源
		fonts, err := fzshengsksjw.GetFont()
		if err != nil {
			log.Fatalln(err)
		}
		imgs, err := images.GetImages()
		if err != nil {
			log.Fatalln(err)
		}

		// 根据用户语言选择字符集
		if isChineseUser {
			zlog.Debug("使用中文验证码")
			builder.SetResources(
				click.WithChars(chars.GetChineseChars()),
				click.WithFonts([]*truetype.Font{fonts}),
				click.WithBackgrounds(imgs),
			)
		} else {
			zlog.Debug("使用英文验证码")
			builder.SetResources(
				click.WithChars(chars.GetAlphaChars()),
				click.WithFonts([]*truetype.Font{fonts}),
				click.WithBackgrounds(imgs),
			)
		}

		capt = builder.Make()
	}

	// 其余代码保持不变
	captData, err := capt.Generate()
	if err != nil {
		log.Fatalln(err)
	}

	dotData := captData.GetData()
	if dotData == nil {
		bt, _ := json.Marshal(map[string]interface{}{
			"code":    1,
			"message": "gen captcha data failed",
		})
		_, _ = fmt.Fprintf(w, string(bt))
		return
	}

	var masterImageBase64, thumbImageBase64 string
	masterImageBase64, err = captData.GetMasterImage().ToBase64()
	if err != nil {
		bt, _ := json.Marshal(map[string]interface{}{
			"code":    1,
			"message": "base64 data failed",
		})
		_, _ = fmt.Fprintf(w, string(bt))
		return
	}

	thumbImageBase64, err = captData.GetThumbImage().ToBase64()
	if err != nil {
		bt, _ := json.Marshal(map[string]interface{}{
			"code":    1,
			"message": "base64 data failed",
		})
		_, _ = fmt.Fprintf(w, string(bt))
		return
	}

	dotsByte, _ := json.Marshal(dotData)
	key := uuid.NewV4().String()
	//key := helper.StringToMD5(string(dotsByte))
	s.cache.SetWithTTl(enums.CACHE_CAPTCHA_TRY+key, dotsByte, 1*time.Minute)

	bt, _ := json.Marshal(map[string]interface{}{
		"code":         0,
		"captcha_key":  key,
		"image_base64": masterImageBase64,
		"thumb_base64": thumbImageBase64,
	})

	_, _ = fmt.Fprintf(w, string(bt))
}

// VerifyCaptcha 验证验证码
func (s *CaptchaService) VerifyCaptcha(w http.ResponseWriter, r *http.Request, captchaType string, expireTime int, webLog innerbean.WebLog) {
	code := 1
	_ = r.ParseForm()
	dots := r.Form.Get("dots")
	key := r.Form.Get("key")
	if dots == "" || key == "" {
		bt, _ := json.Marshal(map[string]interface{}{
			"code":    code,
			"message": "dots or key param is empty",
		})
		_, _ = fmt.Fprintf(w, string(bt))
		return
	}

	cacheDataByte, err := s.cache.GetBytes(enums.CACHE_CAPTCHA_TRY + key)
	if err != nil {
		bt, _ := json.Marshal(map[string]interface{}{
			"code":    code,
			"message": "illegal key",
		})
		_, _ = fmt.Fprintf(w, string(bt))
		return
	}
	s.cache.Remove(enums.CACHE_CAPTCHA_TRY + key)
	if len(cacheDataByte) == 0 {
		bt, _ := json.Marshal(map[string]interface{}{
			"code":    code,
			"message": "illegal key",
		})
		_, _ = fmt.Fprintf(w, string(bt))
		return
	}
	src := strings.Split(dots, ",")

	var dct map[int]*click.Dot
	if err := json.Unmarshal(cacheDataByte, &dct); err != nil {
		bt, _ := json.Marshal(map[string]interface{}{
			"code":    code,
			"message": "illegal key",
		})
		_, _ = fmt.Fprintf(w, string(bt))
		return
	}

	chkRet := false
	if (len(dct) * 2) == len(src) {
		for i := 0; i < len(dct); i++ {
			dot := dct[i]
			j := i * 2
			k := i*2 + 1
			sx, _ := strconv.ParseFloat(fmt.Sprintf("%v", src[j]), 64)
			sy, _ := strconv.ParseFloat(fmt.Sprintf("%v", src[k]), 64)

			chkRet = click.CheckPoint(int64(sx), int64(sy), int64(dot.X), int64(dot.Y), int64(dot.Width), int64(dot.Height), 0)
			if !chkRet {
				break
			}
		}
	}

	if chkRet {
		code = 0
		// 生成验证通过的标识
		captchaPassToken := uuid.NewV4().String()
		// 将标识存入缓存
		s.cache.SetWithTTl(enums.CACHE_CAPTCHA_PASS+captchaPassToken+webLog.SRC_IP, "ok", time.Duration(expireTime)*time.Hour)

		// 设置Cookie
		cookie := &http.Cookie{
			Name:     "samwaf_captcha_token",
			Value:    captchaPassToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   r.TLS != nil, // 如果是HTTPS请求则设置Secure
			MaxAge:   expireTime * 3600,
		}
		http.SetCookie(w, cookie)

		// 同时在响应头中也设置验证标识
		w.Header().Set("X-SamWaf-Captcha-Token", captchaPassToken)
		webLog.ACTION = "放行"
		webLog.RULE = "图形验证码验证通过"
		global.GQEQUE_LOG_DB.Enqueue(webLog)
	} else {
		webLog.ACTION = "禁止"
		webLog.RULE = "图形验证码验证失败"
		global.GQEQUE_LOG_DB.Enqueue(webLog)
	}

	bt, _ := json.Marshal(map[string]interface{}{
		"code": code,
	})
	_, _ = fmt.Fprintf(w, string(bt))
	return
}

// ShowCaptchaHomePage 显示验证码首页
func (s *CaptchaService) ShowCaptchaHomePage(w http.ResponseWriter, r *http.Request) {
	// 设置内容类型
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// 从指定目录加载index.html
	http.ServeFile(w, r, utils.GetCurrentDir()+"/data/captcha/index.html")
}

// 辅助函数

// writeJSONResponse 写入JSON响应
func writeJSONResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// generateRandomKey 生成随机密钥
func generateRandomKey() string {
	// 实际实现中应该使用更安全的随机数生成方法
	return "random_key_123456"
}

// generateImageBase64 生成图片的Base64编码
func generateImageBase64() string {
	// 实际实现中应该生成真实的验证码图片
	return "base64_encoded_image_data"
}

// generateThumbBase64 生成缩略图的Base64编码
func generateThumbBase64() string {
	// 实际实现中应该生成真实的缩略图
	return "base64_encoded_thumb_data"
}
