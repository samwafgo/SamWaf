package wafcaptcha

import (
	"SamWaf/cache"
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/utils"
	"encoding/json"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang/freetype/truetype"
	capserver "github.com/samwafgo/cap_go_server"
	"github.com/wenlng/go-captcha-assets/bindata/chars"
	"github.com/wenlng/go-captcha-assets/resources/fonts/fzshengsksjw"
	"github.com/wenlng/go-captcha-assets/resources/images"
	"github.com/wenlng/go-captcha/v2/base/option"
	"github.com/wenlng/go-captcha/v2/click"
	"go.uber.org/zap"
)

var (
	captchaService *CaptchaService
	once           sync.Once
)

// CaptchaService 验证码服务结构体
type CaptchaService struct {
	cache cache.CacheStore
	//text
	textCapt      click.Captcha
	lightTextCapt click.Captcha
	//capJs
	capJsCapt *capserver.Cap
}

// InitCaptchaService 初始化验证码服务，传入缓存引用
func InitCaptchaService(cache cache.CacheStore) {
	once.Do(func() {
		captchaService = &CaptchaService{
			cache: cache,
			capJsCapt: capserver.New(&capserver.CapConfig{
				NoFSState: false,
			}),
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
func (s *CaptchaService) HandleCaptchaRequest(w http.ResponseWriter, r *http.Request, weblog *innerbean.WebLog, captchaConfig model.CaptchaConfig, pathPrefix string, ipMode string) {

	path := r.URL.Path
	// 记录访问日志
	zlog.Debug("验证码请求", zap.String("path", path), zap.String("method", r.Method), zap.String("remote_addr", r.RemoteAddr), zap.String("path_prefix", pathPrefix))

	// 规范化路径前缀，确保以/开头且不以/结尾
	if pathPrefix == "" {
		pathPrefix = "/samwaf_captcha"
	}
	captchaPath := strings.TrimSuffix(pathPrefix, "/")

	// 只对 capJs 做特判，其余一律走传统方式。
	// 早先这里是「两个 if、没有 else」：配置里出现不认识的验证方式时两个分支都不进，
	// 函数什么都不写就返回，调用方紧接着 return —— 响应体是空的、挑战永远发不出来。
	// 解析入口 model.ParseCaptchaConfig 已做归一化，这里再兜一层，防止绕过解析的调用方。
	if captchaConfig.EngineType != model.CaptchaEngineCapJs {
		//传统方式的验证码处理
		if strings.HasPrefix(path, captchaPath+"/click_basic") {
			s.GetClickBasicCaptData(w, r)
		} else if strings.HasPrefix(path, captchaPath+"/verify") {
			// 根据请求参数确定验证码类型
			captchaType := r.URL.Query().Get("type")
			s.VerifyCaptcha(w, r, captchaType, weblog, captchaConfig, ipMode)
		} else if strings.HasPrefix(path, captchaPath+"/") {
			cleanPath := strings.TrimPrefix(path, captchaPath+"/")
			s.ServeStaticFile(w, r, cleanPath, captchaConfig)
		} else {
			// 记录日志信息
			weblog.ACTION = "禁止"
			// 保留上游已写入的触发原因（例如 CC 规则的人机验证动作），
			// 直接覆盖会让日志里只剩"显示图形验证码"，查不出是哪条规则要求验证的
			if weblog.RULE != "" {
				weblog.RULE = weblog.RULE + " / 显示图形验证码"
			} else {
				weblog.RULE = "显示图形验证码"
			}
			global.GQEQUE_LOG_DB.Enqueue(weblog)
			// 默认显示验证码选择页面
			s.ShowCaptchaHomePage(w, r, captchaConfig, pathPrefix, weblog.REQ_UUID)
		}
	} else {
		//基于工作量证明的验证码处理
		if strings.HasPrefix(path, captchaPath+"/challenge") {
			s.GetCapJsChallenge(w, r, captchaConfig)
		} else if strings.HasPrefix(path, captchaPath+"/redeem") {
			s.VerifyCapJsCaptcha(w, r, captchaConfig)
		} else if strings.HasPrefix(path, captchaPath+"/validate") {
			s.ValidateCapJsCaptcha(w, r, captchaConfig, weblog, ipMode)
		} else if strings.HasPrefix(path, captchaPath+"/") {
			cleanPath := strings.TrimPrefix(path, captchaPath+"/")
			s.ServeStaticFile(w, r, cleanPath, captchaConfig)
		} else {
			// 记录日志信息
			weblog.ACTION = "禁止"
			// 保留上游已写入的触发原因（例如 CC 规则的人机验证动作），
			// 直接覆盖会让日志里只剩"显示CapJs验证码"，查不出是哪条规则要求验证的
			if weblog.RULE != "" {
				weblog.RULE = weblog.RULE + " / 显示CapJs验证码"
			} else {
				weblog.RULE = "显示CapJs验证码"
			}
			global.GQEQUE_LOG_DB.Enqueue(weblog)
			// 默认显示验证码选择页面
			s.ShowCaptchaHomePage(w, r, captchaConfig, pathPrefix, weblog.REQ_UUID)
		}
	}

}

// ServeStaticFile 提供静态文件服务
func (s *CaptchaService) ServeStaticFile(w http.ResponseWriter, r *http.Request, filePath string, captchaConfig model.CaptchaConfig) {
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
	} else if strings.HasSuffix(cleanPath, "wasm") {
		w.Header().Set("Content-Type", "application/wasm")
	}

	// 构建安全的完整路径
	basePath := utils.GetCurrentDir() + "/data/captcha/"
	if captchaConfig.EngineType == "capJs" {
		basePath = utils.GetCurrentDir() + "/data/capjs/"
	}
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
	key := uuid.GenUUID()
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
func (s *CaptchaService) VerifyCaptcha(w http.ResponseWriter, r *http.Request, captchaType string, webLog *innerbean.WebLog, captchaConfig model.CaptchaConfig, ipMode string) {
	// 根据IP模式选择使用的IP（从 Host 级别传入）
	clientIP := model.GetClientIPByMode(ipMode, webLog.NetSrcIp, webLog.SRC_IP)
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
		captchaPassToken := uuid.GenUUID()
		// 将标识存入缓存
		s.cache.SetWithTTl(enums.CACHE_CAPTCHA_PASS+captchaPassToken+clientIP, "ok", time.Duration(captchaConfig.ExpireTime)*time.Hour)

		// 设置Cookie
		cookie := &http.Cookie{
			Name:     "samwaf_captcha_token",
			Value:    captchaPassToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   r.TLS != nil, // 如果是HTTPS请求则设置Secure
			MaxAge:   int(captchaConfig.ExpireTime) * 3600,
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
// injectReqUUID 把本次请求的访问识别码放进挑战页。
//
// 优先替换页面里的 [[.SAMWAF_REQ_UUID]] 占位符——改过挑战页的用户可以自己决定它出现在哪里；
// 页面里没有占位符（用户用的是自己改造过的旧页面）就在 </body> 前补一块。
// 这样识别码不依赖"把内置页面覆盖回去"才能生效，用户改过的挑战页一个字都不用动。
func injectReqUUID(htmlStr, reqUUID string) string {
	if reqUUID == "" {
		return htmlStr
	}
	esc := html.EscapeString(reqUUID)
	if strings.Contains(htmlStr, reqUUIDPlaceholder) {
		return strings.ReplaceAll(htmlStr, reqUUIDPlaceholder, esc)
	}
	block := `<div style="margin:10px auto;text-align:center;font-size:12px;color:#8a8f99;word-break:break-all">` +
		`识别码 / Ref: <code style="font-family:Consolas,Menlo,monospace">` + esc + `</code></div>`
	if i := strings.LastIndex(htmlStr, "</body>"); i >= 0 {
		return htmlStr[:i] + block + htmlStr[i:]
	}
	return htmlStr + block
}

// reqUUIDPlaceholder 与拦截页模板同名，改过挑战页的用户照抄这个占位符即可自定义位置
const reqUUIDPlaceholder = "[[.SAMWAF_REQ_UUID]]"

// 挑战页上的「管理员联系方式」占位与包裹标记。
// 用一对注释把整块圈起来，是为了让「没填就不显示」能干净地做到——
// 只替换占位符的话，留下的空壳 div 还占着边距，看起来像页面坏了一块。
const (
	contactPlaceholder = "[[.SAMWAF_CONTACT]]"
	contactBeginMarker = "<!--SAMWAF_CONTACT_BEGIN-->"
	contactEndMarker   = "<!--SAMWAF_CONTACT_END-->"
)

// injectContact 把管理员联系方式渲染进挑战页；contact 为空则整块不渲染。
//
// 挑战页是访客的死胡同：被挡下来之后进不去、也没地方问。填了联系方式就给一条出路。
// 内容是管理端自由填写的文本，出现在**给访客看的公开页面**上，因此一律 HTML 转义后再放进文本节点，
// 不拼进任何属性或脚本上下文。
func injectContact(htmlStr, contact string) string {
	contact = strings.TrimSpace(contact)
	begin := strings.Index(htmlStr, contactBeginMarker)
	end := strings.Index(htmlStr, contactEndMarker)
	hasBlock := begin >= 0 && end > begin

	if contact == "" {
		if hasBlock {
			return htmlStr[:begin] + htmlStr[end+len(contactEndMarker):]
		}
		// 模板被改过、标记不在了：把占位符擦掉，别把它原样显示给访客
		return strings.ReplaceAll(htmlStr, contactPlaceholder, "")
	}

	esc := html.EscapeString(contact)
	if hasBlock {
		out := htmlStr[:begin] + htmlStr[begin+len(contactBeginMarker):end] + htmlStr[end+len(contactEndMarker):]
		return strings.ReplaceAll(out, contactPlaceholder, esc)
	}
	if strings.Contains(htmlStr, contactPlaceholder) {
		return strings.ReplaceAll(htmlStr, contactPlaceholder, esc)
	}
	// 模板里既没有标记也没有占位符（用户自定义过）：兜底追加，宁可样式朴素也别把联系方式弄丢
	block := `<div style="margin:10px auto;text-align:center;font-size:12px;color:#8a8f99;` +
		`word-break:break-all;white-space:pre-line">` + esc + `</div>`
	if i := strings.LastIndex(htmlStr, "</body>"); i >= 0 {
		return htmlStr[:i] + block + htmlStr[i:]
	}
	return htmlStr + block
}

// ShowCaptchaHomePage 渲染验证码挑战页。
//
// reqUUID 是本次请求的访问识别码，页面上以「[[.SAMWAF_REQ_UUID]]」占位。
// 访客侧只给这个每请求随机的码：管理员拿它在防御日志里一搜，触发的规则、时间、来源 IP 全都有；
// 而页面上放任何随请求稳定的标识，都会让人反复试探出自己命中或绕过了哪条规则。
func (s *CaptchaService) ShowCaptchaHomePage(w http.ResponseWriter, r *http.Request, configStruct model.CaptchaConfig, pathPrefix string, reqUUID string) {
	// 设置内容类型
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	if pathPrefix == "" {
		pathPrefix = "/samwaf_captcha"
	}

	// 同 HandleCaptchaRequest：只特判 capJs，其余走传统页，避免不认识的取值渲染出一个空响应
	if configStruct.EngineType != model.CaptchaEngineCapJs {
		// 读取HTML模板文件
		htmlPath := utils.GetCurrentDir() + "/data/captcha/index.html"
		htmlContent, err := ioutil.ReadFile(htmlPath)
		if err != nil {
			http.Error(w, "Failed to load page", http.StatusInternalServerError)
			return
		}

		// 替换路径前缀
		htmlStr := string(htmlContent)
		htmlStr = strings.ReplaceAll(htmlStr, "/samwaf_captcha/", pathPrefix+"/")
		htmlStr = strings.ReplaceAll(htmlStr, "'/samwaf_captcha'", "'"+pathPrefix+"'")
		htmlStr = strings.ReplaceAll(htmlStr, "\"/samwaf_captcha\"", "\""+pathPrefix+"\"")
		htmlStr = injectReqUUID(htmlStr, reqUUID)
		htmlStr = injectContact(htmlStr, configStruct.ContactInfo)

		w.Write([]byte(htmlStr))
	} else {
		// 读取HTML模板文件
		htmlPath := utils.GetCurrentDir() + "/data/capjs/index.html"
		htmlContent, err := ioutil.ReadFile(htmlPath)
		if err != nil {
			http.Error(w, "Failed to load page", http.StatusInternalServerError)
			return
		}

		// 准备替换的数据
		htmlStr := string(htmlContent)

		// 替换路径前缀
		htmlStr = strings.ReplaceAll(htmlStr, "/samwaf_captcha/", pathPrefix+"/")
		htmlStr = strings.ReplaceAll(htmlStr, "'/samwaf_captcha'", "'"+pathPrefix+"'")
		htmlStr = strings.ReplaceAll(htmlStr, "\"/samwaf_captcha\"", "\""+pathPrefix+"\"")

		// 替换中文提示信息
		zhInfoTitle := configStruct.CapJsConfig.InfoTitle.Zh
		zhInfoText := configStruct.CapJsConfig.InfoText.Zh
		if zhInfoTitle == "" {
			zhInfoTitle = "安全验证"
		}
		if zhInfoText == "" {
			zhInfoText = "为了确保您的访问安全，请完成以下验证"
		}

		// 替换英文提示信息
		enInfoTitle := configStruct.CapJsConfig.InfoTitle.En
		enInfoText := configStruct.CapJsConfig.InfoText.En
		if enInfoTitle == "" {
			enInfoTitle = "Security Verification"
		}
		if enInfoText == "" {
			enInfoText = "To ensure the security of your access, please complete the following verification"
		}

		// 使用strings.Replace替换HTML中的静态文本
		htmlStr = strings.Replace(htmlStr, "infoTitle: '安全验证',", fmt.Sprintf("infoTitle: '%s',", zhInfoTitle), 1)
		htmlStr = strings.Replace(htmlStr, "infoText: '为了确保您的访问安全，请完成以下验证',", fmt.Sprintf("infoText: '%s',", zhInfoText), 1)
		htmlStr = strings.Replace(htmlStr, "infoTitle: 'Security Verification',", fmt.Sprintf("infoTitle: '%s',", enInfoTitle), 1)
		htmlStr = strings.Replace(htmlStr, "infoText: 'To ensure the security of your access, please complete the following verification',", fmt.Sprintf("infoText: '%s',", enInfoText), 1)

		// 同时替换HTML中的默认显示文本
		htmlStr = strings.Replace(htmlStr, "<h2 id=\"info-title\">安全验证</h2>", fmt.Sprintf("<h2 id=\"info-title\">%s</h2>", zhInfoTitle), 1)
		htmlStr = strings.Replace(htmlStr, "<p id=\"info-text\">为了确保您的访问安全，请完成以下验证</p>", fmt.Sprintf("<p id=\"info-text\">%s</p>", zhInfoText), 1)

		htmlStr = injectReqUUID(htmlStr, reqUUID)
		htmlStr = injectContact(htmlStr, configStruct.ContactInfo)

		// 输出修改后的HTML
		w.Write([]byte(htmlStr))
	}
}

func (s *CaptchaService) GetCapJsChallenge(w http.ResponseWriter, r *http.Request, configStruct model.CaptchaConfig) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	config := &capserver.ChallengeConfig{
		ChallengeCount:      int(configStruct.CapJsConfig.ChallengeCount),
		ChallengeSize:       int(configStruct.CapJsConfig.ChallengeSize),
		ChallengeDifficulty: int(configStruct.CapJsConfig.ChallengeDifficulty),
		ExpiresMs:           int(configStruct.CapJsConfig.ExpiresMs),
		Store:               true,
	}

	challenge, err := s.capJsCapt.CreateChallenge(config)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create challenge: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(challenge)
}

func (s *CaptchaService) VerifyCapJsCaptcha(w http.ResponseWriter, r *http.Request, configStruct model.CaptchaConfig) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	var req struct {
		Token     string          `json:"token"`
		Solutions [][]interface{} `json:"solutions"` // Array of [salt, target, solution] tuples
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Token == "" {
		http.Error(w, "Token is required", http.StatusBadRequest)
		return
	}

	if len(req.Solutions) == 0 {
		http.Error(w, "Solution is required", http.StatusBadRequest)
		return
	}

	// Create solution structure with [salt, target, solution] format
	solution := &capserver.Solution{
		Token:     req.Token,
		Solutions: req.Solutions,
	}

	result, err := s.capJsCapt.RedeemChallenge(solution)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to redeem challenge: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": result.Success,
	}

	if result.Success && result.Token != "" {
		response["token"] = result.Token
	}
	if result.Success && result.Expires > 0 {
		response["expires"] = result.Expires
	}

	json.NewEncoder(w).Encode(response)
}

func (s *CaptchaService) ValidateCapJsCaptcha(w http.ResponseWriter, r *http.Request, configStruct model.CaptchaConfig, webLog *innerbean.WebLog, ipMode string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	var req struct {
		Token string `json:"token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Token == "" {
		http.Error(w, "Token is required", http.StatusBadRequest)
		return
	}

	// 根据IP模式选择使用的IP（从 Host 级别传入）
	clientIP := model.GetClientIPByMode(ipMode, webLog.NetSrcIp, webLog.SRC_IP)

	result, err := s.capJsCapt.ValidateToken(req.Token, nil)
	if err != nil {
		webLog.ACTION = "禁止"
		webLog.RULE = "CapJs验证码验证失败"
		global.GQEQUE_LOG_DB.Enqueue(webLog)
		http.Error(w, fmt.Sprintf("Failed to validate token: %v", err), http.StatusInternalServerError)
		return
	}

	if result.Success {
		// 生成验证通过的标识
		captchaPassToken := uuid.GenUUID()
		// 将标识存入缓存
		s.cache.SetWithTTl(enums.CACHE_CAPTCHA_PASS+captchaPassToken+clientIP, "ok", time.Duration(configStruct.ExpireTime)*time.Hour)

		// 设置Cookie
		cookie := &http.Cookie{
			Name:     "samwaf_captcha_token",
			Value:    captchaPassToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   r.TLS != nil, // 如果是HTTPS请求则设置Secure
			MaxAge:   int(configStruct.ExpireTime) * 3600,
		}
		http.SetCookie(w, cookie)

		// 同时在响应头中也设置验证标识
		w.Header().Set("X-SamWaf-Captcha-Token", captchaPassToken)
		webLog.ACTION = "放行"
		webLog.RULE = "CapJs验证码验证通过"
		global.GQEQUE_LOG_DB.Enqueue(webLog)
	} else {
		webLog.ACTION = "禁止"
		webLog.RULE = "CapJs验证码验证失败"
		global.GQEQUE_LOG_DB.Enqueue(webLog)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": result.Success,
		"message": "1",
	})
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
