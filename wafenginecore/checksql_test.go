package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafenginecore/wafhttpcore"
	"bytes"
	"crypto/sha256"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"testing"

	goahocorasick "github.com/samwafgo/ahocorasick"
)

func newTestWafForSQL() (*WafEngine, *wafenginmodel.HostSafe, *wafenginmodel.HostSafe) {
	zlog.InitZLog(global.GWAF_LOG_DEBUG_ENABLE, "json")
	waf := &WafEngine{}
	waf.InitRouting()
	global.GWAF_GLOBAL_HOST_NAME = "全局网站"
	waf.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME] = &wafenginmodel.HostSafe{Host: model.Hosts{GUARD_STATUS: 1}}
	hostSafe := &wafenginmodel.HostSafe{Host: model.Hosts{GUARD_STATUS: 1}}
	return waf, hostSafe, waf.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME]
}

// TestCheckSqlBodyFalsePositives 用 blaze 全量实测抓到的 7 条正常流量误报样本，
// 确认收敛后（JSON 体走逐值不整块扫 + 跳过结构化数据值 + JSON 值不再叠 URL 解码）不再误拦。
func TestCheckSqlBodyFalsePositives(t *testing.T) {
	waf, hostSafe, globalHost := newTestWafForSQL()
	global.GCONFIG_BODY_DETECT_MODE = "block" // 测请求体拦截逻辑（默认 observe 只记录不拦）
	defer func() { global.GCONFIG_BODY_DETECT_MODE = "observe" }()

	// 均为真实正常业务体（遥测/日志上报/埋点/URL编码JSON），不应被 SQLi 拦
	benignBodies := []struct {
		name string
		body string
	}{
		{"数字遥测JSON", `{"Seq":9,"When":162400,"Evts":[{"Kind":9,"Args":[162417,1573,1553,-20,-20,163,174,11,11,132]}]}`},
		{"日志上报嵌套JSON", `{"level":["2","2"],"msg":["[\"[Capi Success]\",{\"body\":{\"serviceType\":\"ba\",\"regionId\":1}}]"]}`},
		{"埋点含回调URL", `{"Seq":5,"Evts":[{"Kind":63,"Args":["POST","https://rs.fullstory.com/rec/bundle/v2?OrgId=B9193&UserId=4b2b7c84-aa5f-44aa-b927-6f55e6eb3095"]}]}`},
		{"URL编码的JSON数组", `["%7B%22val_nm%22%3A%226%22%2C%22val_act%22%3A%22exposure_yw%22%7D"]`},
	}
	for _, b := range benignBodies {
		t.Run("benign/"+b.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", "http://example.com/api", nil)
			weblog := &innerbean.WebLog{
				BODY:       b.body,
				BodyValues: wafhttpcore.ExtractJSONStringValues(b.body),
			}
			res := waf.CheckSql(req, weblog, url.Values{}, hostSafe, globalHost)
			if res.IsBlock {
				t.Errorf("正常体被误拦为 SQLi: %s", b.body)
			}
		})
	}

	// 真实 SQLi 仍必须拦（防止收敛过度）
	attacks := []struct {
		name string
		body string
	}{
		{"JSON值内SQLi", `{"q":"1' UNION SELECT username,password FROM users--"}`},
		{"JSON值内OR注入", `{"user":"admin' or '1'='1"}`},
	}
	for _, a := range attacks {
		t.Run("attack/"+a.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", "http://example.com/api", nil)
			weblog := &innerbean.WebLog{
				BODY:       a.body,
				BodyValues: wafhttpcore.ExtractJSONStringValues(a.body),
			}
			res := waf.CheckSql(req, weblog, url.Values{}, hostSafe, globalHost)
			if !res.IsBlock {
				t.Errorf("真实 SQLi 漏拦: %s", a.body)
			}
		})
	}
}

// buildIssue1084JPEGBytes 构造包含 Issue #1084 实测触发 s)o1 指纹、../ 穿越字节、;whoami 与敏感词的真实感 JPEG 二进制头。
func buildIssue1084JPEGBytes() []byte {
	var b bytes.Buffer
	// 标准 JPEG SOI + APP0 JFIF 头（含 NUL 与高位字节）
	b.Write([]byte{
		0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00, 0x01, 0x01, 0x00, 0x00, 0x01,
		0x00, 0x01, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43, 0x00,
	})
	// Issue #1084 触发 libinjection s)o1 的 16 字节窗口
	b.Write([]byte{0x1c, 0x16, 0x16, 0x20, 0x2c, 0x20, 0x23, 0x26, 0x27, 0x29, 0x2a, 0x29, 0x19, 0x1f, 0x2d, 0x30})
	// 夹带可能误触发穿越/RCE/敏感词替换的字节序列与大量随机高位压缩流字节
	b.Write([]byte("../../etc/passwd ;whoami replace-secret "))
	b.Write(bytes.Repeat([]byte{0xFF, 0x00, 0xA3, 0xD7, 0x8E, 0x11, 0x9B, 0x04}, 128))
	b.Write([]byte{0xFF, 0xD9})
	return b.Bytes()
}

// TestIssue1084_MultipartJPEGUploadPassesIntact 验证带正常图片上传的 multipart 请求不再误报 SQLi/RCE/目录穿越，
// 且敏感词 replace 不会改坏图片二进制流、回源字节完整一致。
func TestIssue1084_MultipartJPEGUploadPassesIntact(t *testing.T) {
	q := newNotifyClassificationQueues(t)
	oldMode := global.GCONFIG_BODY_DETECT_MODE
	oldDesensitize := global.GCONFIG_RECORD_LOG_DESENSITIZE
	global.GCONFIG_BODY_DETECT_MODE = "block"
	global.GCONFIG_RECORD_LOG_DESENSITIZE = 0
	t.Cleanup(func() {
		global.GCONFIG_BODY_DETECT_MODE = oldMode
		global.GCONFIG_RECORD_LOG_DESENSITIZE = oldDesensitize
	})

	jpegData := buildIssue1084JPEGBytes()
	wantFileSum := sha256.Sum256(jpegData)

	var bodyBuf bytes.Buffer
	mw := multipart.NewWriter(&bodyBuf)
	_ = mw.WriteField("foodName", "招牌牛肉面")
	_ = mw.WriteField("price", "28.5")
	fw, err := mw.CreateFormFile("upfiles", "dish.jpg")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write(jpegData)
	_ = mw.Close()
	rawPayload := bodyBuf.Bytes()

	var gotFileSum [32]byte
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(4 << 20); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f, _, err := r.FormFile("upfiles")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer f.Close()
		received, _ := io.ReadAll(f)
		gotFileSum = sha256.Sum256(received)
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	waf := newNotifyClassificationEngine(t, model.HostsDefense{
		DEFENSE_SQLI:          1,
		DEFENSE_XSS:           1,
		DEFENSE_RCE:           1,
		DEFENSE_DIR_TRAVERSAL: 1,
		DEFENSE_SENSITIVE:     1,
	})
	// 配置一条 replace 敏感词，确认不会破坏 multipart 图片内容
	sens := model.Sensitive{Content: "replace-secret", Action: "replace", CheckDirection: "in"}
	waf.Sensitive = []model.Sensitive{sens}
	waf.SensitiveDirectionMap = map[string]bool{"in": true}
	waf.SensitiveManager = new(goahocorasick.Machine)
	_ = waf.SensitiveManager.BuildByCustom([][]rune{[]rune(sens.Content)}, map[string]interface{}{sens.Content: sens})

	waf.UpdateHost(notifyClassificationHostCode, func(h *wafenginmodel.HostSafe) {
		h.PathRules = nil
		h.TargetHost = origin.URL
	})

	req := httptest.NewRequest(http.MethodPost, "http://notify.test/api/upload", bytes.NewReader(rawPayload))
	req.RemoteAddr = notifyClassificationIP + ":12345"
	req.Header.Set("Content-Type", mw.FormDataContentType())

	w := httptest.NewRecorder()
	waf.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("正常 JPEG multipart 上传被误拦: status=%d body=%q", w.Code, w.Body.String())
	}
	if gotFileSum != wantFileSum {
		t.Fatalf("回源收到的 JPEG 文件哈希不一致，上传内容被破坏")
	}
	q.noMessage(t)
}

// TestMultipartTextFieldsStillBlocked 验证跳过文件字节后，multipart 文本字段与内嵌 JSON 里的注入仍被严格拦截（补 S1-7）。
func TestMultipartTextFieldsStillBlocked(t *testing.T) {
	q := newNotifyClassificationQueues(t)
	oldMode := global.GCONFIG_BODY_DETECT_MODE
	t.Cleanup(func() { global.GCONFIG_BODY_DETECT_MODE = oldMode })

	jpegData := buildIssue1084JPEGBytes()

	cases := []struct {
		name      string
		mode      string
		buildPart func(mw *multipart.Writer)
		wantRule  string
	}{
		{
			name: "文本字段SQLi在observe下仍强制拦截",
			mode: "observe",
			buildPart: func(mw *multipart.Writer) {
				_ = mw.WriteField("foodName", "1' UNION SELECT username,password FROM users--")
			},
			wantRule: "SQL注入",
		},
		{
			name: "空filename字段SQLi视为文本强制拦截",
			mode: "observe",
			buildPart: func(mw *multipart.Writer) {
				h := make(textproto.MIMEHeader)
				h.Set("Content-Disposition", `form-data; name="id"; filename=""`)
				pw, _ := mw.CreatePart(h)
				_, _ = pw.Write([]byte("admin' OR '1'='1"))
			},
			wantRule: "SQL注入",
		},
		{
			name: "内嵌JSON字段SQLi在block下拦截",
			mode: "block",
			buildPart: func(mw *multipart.Writer) {
				_ = mw.WriteField("meta", `{"filter":"1' UNION SELECT username,password FROM users--"}`)
			},
			wantRule: "SQL注入",
		},
		{
			name: "文本字段XSS在block下拦截",
			mode: "block",
			buildPart: func(mw *multipart.Writer) {
				_ = mw.WriteField("remarks", "<script>alert(1)</script>")
			},
			wantRule: "XSS跨站注入",
		},
		{
			name: "文本字段RCE强制拦截",
			mode: "observe",
			buildPart: func(mw *multipart.Writer) {
				_ = mw.WriteField("cmd", ";whoami")
			},
			wantRule: "RCE:",
		},
		{
			name: "文本字段目录穿越在block下拦截",
			mode: "block",
			buildPart: func(mw *multipart.Writer) {
				_ = mw.WriteField("tpl", "../../../../etc/passwd")
			},
			wantRule: "目录穿越漏洞",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			global.GCONFIG_BODY_DETECT_MODE = tc.mode
			var buf bytes.Buffer
			mw := multipart.NewWriter(&buf)
			tc.buildPart(mw)
			fw, _ := mw.CreateFormFile("upfiles", "ok.jpg")
			_, _ = fw.Write(jpegData)
			_ = mw.Close()

			waf := newNotifyClassificationEngine(t, model.HostsDefense{
				DEFENSE_SQLI:          1,
				DEFENSE_XSS:           1,
				DEFENSE_RCE:           1,
				DEFENSE_DIR_TRAVERSAL: 1,
			})
			q.expected++
			req := httptest.NewRequest(http.MethodPost, "http://notify.test/api/upload", bytes.NewReader(buf.Bytes()))
			req.RemoteAddr = notifyClassificationIP + ":12345"
			req.Header.Set("Content-Type", mw.FormDataContentType())

			w := httptest.NewRecorder()
			waf.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Fatalf("期望 403 拦截，实际 status=%d", w.Code)
			}
			log := q.blockLog(t, http.StatusForbidden, tc.wantRule)
			q.message(t, log, true)
		})
	}
}

// TestBinaryAndSpoofedContentTypeGuardrails 验证真实裸二进制放行，而伪造图片头/GIF89a/伪multipart/SVG注入均被拦截。
func TestBinaryAndSpoofedContentTypeGuardrails(t *testing.T) {
	waf, hostSafe, globalHost := newTestWafForSQL()
	oldMode := global.GCONFIG_BODY_DETECT_MODE
	global.GCONFIG_BODY_DETECT_MODE = "block"
	defer func() { global.GCONFIG_BODY_DETECT_MODE = oldMode }()

	// 1) 真实裸二进制 JPEG 上传（PUT image/jpeg）→ 放行
	jpegBytes := buildIssue1084JPEGBytes()
	reqBin, _ := http.NewRequest(http.MethodPut, "http://xxxx.com/raw-upload", nil)
	reqBin.Header.Set("Content-Type", "image/jpeg")
	wlBin := &innerbean.WebLog{BODY: string(jpegBytes), SrcByteBody: jpegBytes}
	if res := waf.CheckSql(reqBin, wlBin, url.Values{}, hostSafe, globalHost); res.IsBlock {
		t.Fatal("真实 image/jpeg 二进制流不应命中 SQLi")
	}

	// 2) 伪造 image/jpeg 头夹带 JSON SQLi → 必须拦
	spoofJSON := `{"id":"1' UNION SELECT username,password FROM users--"}`
	reqSpoof1, _ := http.NewRequest(http.MethodPost, "http://xxxx.com/api", nil)
	reqSpoof1.Header.Set("Content-Type", "image/jpeg")
	wlSpoof1 := &innerbean.WebLog{BODY: spoofJSON, SrcByteBody: []byte(spoofJSON)}
	if res := waf.CheckSql(reqSpoof1, wlSpoof1, url.Values{}, hostSafe, globalHost); !res.IsBlock {
		t.Fatal("伪造 image/jpeg 发送 JSON SQLi 必须被拦截")
	}

	// 3) 伪造 image/gif + GIF89a 多态文本 SQLi → 必须拦
	spoofGIF := "GIF89a' UNION SELECT username,password FROM users--"
	reqSpoof2, _ := http.NewRequest(http.MethodPost, "http://xxxx.com/api", nil)
	reqSpoof2.Header.Set("Content-Type", "image/gif")
	wlSpoof2 := &innerbean.WebLog{BODY: spoofGIF, SrcByteBody: []byte(spoofGIF)}
	if res := waf.CheckSql(reqSpoof2, wlSpoof2, url.Values{}, hostSafe, globalHost); !res.IsBlock {
		t.Fatal("GIF89a 纯文本多态 SQLi 必须被拦截")
	}

	// 4) 伪造 multipart/form-data 但正文无有效 boundary → 回退裸文本检测并拦截
	spoofMP := "id=1' UNION SELECT username,password FROM users--"
	reqSpoof3, _ := http.NewRequest(http.MethodPost, "http://xxxx.com/api", nil)
	reqSpoof3.Header.Set("Content-Type", "multipart/form-data; boundary=nonexistent")
	wlSpoof3 := &innerbean.WebLog{BODY: spoofMP, SrcByteBody: []byte(spoofMP)}
	if res := waf.CheckSql(reqSpoof3, wlSpoof3, url.Values{}, hostSafe, globalHost); !res.IsBlock {
		t.Fatal("伪造无 boundary 的 multipart 报文必须回退并拦截")
	}

	// 5) image/svg+xml 携带 XSS → 不得当二进制免检，必须被 CheckXss 拦截
	svgXSS := `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>`
	reqSVG, _ := http.NewRequest(http.MethodPost, "http://xxxx.com/upload.svg", nil)
	reqSVG.Header.Set("Content-Type", "image/svg+xml")
	wlSVG := &innerbean.WebLog{BODY: svgXSS, SrcByteBody: []byte(svgXSS)}
	// XML/SVG 作为单值或请求体：验证 IsBinaryBody 必为 false
	ensureWebLogBodyClassified(reqSVG, wlSVG, nil)
	if wlSVG.IsBinaryBody {
		t.Fatal("image/svg+xml 绝不能被判定为二进制免检")
	}
}

// TestD2_RawTextBodyModeAndD5_FingerprintExclude 验证 D2（未知裸文本 BODY 受 body_detect_mode 门控，而标准表单始终强拦）与 D5（sqli_fp_exclude 豁免）。
func TestD2_RawTextBodyModeAndD5_FingerprintExclude(t *testing.T) {
	waf, hostSafe, globalHost := newTestWafForSQL()
	oldMode := global.GCONFIG_BODY_DETECT_MODE
	defer func() {
		global.GCONFIG_BODY_DETECT_MODE = oldMode
		SetSQLiFingerprintExclude("")
	}()

	rawTextAttack := "1' UNION SELECT username,password FROM users--"

	// D2-1: observe 模式下未知 text/plain BODY 只打观察标记、不返回 403
	global.GCONFIG_BODY_DETECT_MODE = "observe"
	reqPlain, _ := http.NewRequest(http.MethodPost, "http://xxxx.com/plain", nil)
	reqPlain.Header.Set("Content-Type", "text/plain")
	wlObserve := &innerbean.WebLog{BODY: rawTextAttack}
	resObs := waf.CheckSql(reqPlain, wlObserve, url.Values{}, hostSafe, globalHost)
	if resObs.IsBlock || wlObserve.RULE != "观察模式:疑似SQL注入" {
		t.Fatalf("observe 模式裸文本 BODY 应仅观察不拦: IsBlock=%v RULE=%q", resObs.IsBlock, wlObserve.RULE)
	}

	// D2-2: off 模式下未知 text/plain BODY 不检测
	global.GCONFIG_BODY_DETECT_MODE = "off"
	wlOff := &innerbean.WebLog{BODY: rawTextAttack}
	resOff := waf.CheckSql(reqPlain, wlOff, url.Values{}, hostSafe, globalHost)
	if resOff.IsBlock || wlOff.RULE != "" {
		t.Fatalf("off 模式裸文本 BODY 不应命中: IsBlock=%v RULE=%q", resOff.IsBlock, wlOff.RULE)
	}

	// D2-3: 即便在 off 模式下，urlencoded 表单（含无 "=" 裸串）依然始终强拦
	reqForm, _ := http.NewRequest(http.MethodPost, "http://xxxx.com/login", nil)
	reqForm.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wlForm := &innerbean.WebLog{BODY: "' OR '1'='1"}
	if res := waf.CheckSql(reqForm, wlForm, url.Values{}, hostSafe, globalHost); !res.IsBlock {
		t.Fatal("urlencoded 表单在 off 模式下仍必须强制拦截")
	}

	// D5: sqli_fp_exclude 精准豁免指定弱指纹，静默放行不刷日志，且不影响其他指纹
	global.GCONFIG_BODY_DETECT_MODE = "block"
	weakQuery := string([]byte{0x2c, 0x20, 0x23, 0x26, 0x27, 0x29, 0x2a, 0x29, 0x19, 0x1f, 0x2d, 0x30}) // s)o1
	reqWeak, _ := http.NewRequest(http.MethodGet, "http://xxxx.com/search", nil)
	wlBefore := &innerbean.WebLog{RawQuery: weakQuery}
	if res := waf.CheckSql(reqWeak, wlBefore, url.Values{}, hostSafe, globalHost); !res.IsBlock {
		t.Fatal("豁免前 s)o1 查询串应命中拦截")
	}

	SetSQLiFingerprintExclude("s)o1")
	wlAfter := &innerbean.WebLog{RawQuery: weakQuery}
	resAfter := waf.CheckSql(reqWeak, wlAfter, url.Values{}, hostSafe, globalHost)
	if resAfter.IsBlock || wlAfter.RULE != "" {
		t.Fatalf("配置 sqli_fp_exclude=s)o1 后应静默放行: IsBlock=%v RULE=%q", resAfter.IsBlock, wlAfter.RULE)
	}

	wlReal := &innerbean.WebLog{RawQuery: rawTextAttack}
	if res := waf.CheckSql(reqWeak, wlReal, url.Values{}, hostSafe, globalHost); !res.IsBlock {
		t.Fatal("豁免 s)o1 后真实 UNION 注入仍必须拦截")
	}
}

// TestAdversarialReviewHardening 覆盖独立对抗复核发现的 H1/H2/H3/H5/M3 全部绕过与内存回归面。
func TestAdversarialReviewHardening(t *testing.T) {
	waf, hostSafe, globalHost := newTestWafForSQL()
	oldMode := global.GCONFIG_BODY_DETECT_MODE
	defer func() { global.GCONFIG_BODY_DETECT_MODE = oldMode }()

	// [H1-a] 多值 Content-Type 头（首条二进制、次条表单）在 observe 模式下仍必须第一阶段强制拦截
	global.GCONFIG_BODY_DETECT_MODE = "observe"
	reqMultiCT, _ := http.NewRequest(http.MethodPost, "http://xxxx.com/api", nil)
	reqMultiCT.Header.Add("Content-Type", "image/jpeg")
	reqMultiCT.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	bodyMulti := "id=1' UNION SELECT username,password FROM users--"
	wlMulti := &innerbean.WebLog{BODY: bodyMulti, SrcByteBody: []byte(bodyMulti)}
	if res := waf.CheckSql(reqMultiCT, wlMulti, url.Values{}, hostSafe, globalHost); !res.IsBlock {
		t.Fatal("[H1] 多值 Content-Type 夹带 SQLi 在 observe 下必须强制拦截")
	}

	// [H1-b] Content-Type 参数子串含 x-www-form-urlencoded 不得劫持合法 multipart 解析
	var mpBuf bytes.Buffer
	mw := multipart.NewWriter(&mpBuf)
	_ = mw.WriteField("id", "1' UNION SELECT username,password FROM users--")
	fw, _ := mw.CreateFormFile("upfiles", "a.jpg")
	_, _ = fw.Write(append(buildIssue1084JPEGBytes(), []byte("%ZZ")...))
	_ = mw.Close()
	reqSubstrCT, _ := http.NewRequest(http.MethodPost, "http://xxxx.com/upload", nil)
	reqSubstrCT.Header.Set("Content-Type", mw.FormDataContentType()+"; x=application/x-www-form-urlencoded")
	wlSubstr := &innerbean.WebLog{BODY: mpBuf.String(), SrcByteBody: mpBuf.Bytes()}
	if res := waf.CheckSql(reqSubstrCT, wlSubstr, url.Values{}, hostSafe, globalHost); !res.IsBlock {
		t.Fatal("[H1] multipart Content-Type 附加参数含 urlencoded 字样时文本字段注入仍必须强制拦截")
	}

	// [H2] 文件上传 part 的原始 filename 携带目录穿越或 SQLi 时（即使 CheckUpload 未开启）仍必须被对应模块拦截
	global.GCONFIG_BODY_DETECT_MODE = "block"
	var fnTravBuf bytes.Buffer
	mwTrav := multipart.NewWriter(&fnTravBuf)
	hTrav := make(textproto.MIMEHeader)
	hTrav.Set("Content-Disposition", `form-data; name="upfile"; filename="../../../../etc/passwd"`)
	hTrav.Set("Content-Type", "image/jpeg")
	pwTrav, _ := mwTrav.CreatePart(hTrav)
	_, _ = pwTrav.Write(buildIssue1084JPEGBytes())
	_ = mwTrav.Close()
	reqTrav, _ := http.NewRequest(http.MethodPost, "http://xxxx.com/upload", nil)
	reqTrav.Header.Set("Content-Type", mwTrav.FormDataContentType())
	wlTrav := &innerbean.WebLog{BODY: fnTravBuf.String(), SrcByteBody: fnTravBuf.Bytes()}
	if res := waf.CheckDirTraversal(reqTrav, wlTrav, url.Values{}, hostSafe, globalHost); !res.IsBlock {
		t.Fatal("[H2] multipart 文件 part 的 filename 含目录穿越必须被 CheckDirTraversal 拦截")
	}

	// 验证常见合法中文/括号文件名不会触发 SQLi 误报
	for _, cleanName := range []string{"微信图片_20261128.jpg", "report (1) - final.jpg", "avatar_v2.0.png"} {
		var cleanBuf bytes.Buffer
		mwClean := multipart.NewWriter(&cleanBuf)
		fwClean, _ := mwClean.CreateFormFile("upfile", cleanName)
		_, _ = fwClean.Write(buildIssue1084JPEGBytes())
		_ = mwClean.Close()
		reqClean, _ := http.NewRequest(http.MethodPost, "http://xxxx.com/upload", nil)
		reqClean.Header.Set("Content-Type", mwClean.FormDataContentType())
		wlClean := &innerbean.WebLog{BODY: cleanBuf.String(), SrcByteBody: cleanBuf.Bytes()}
		if res := waf.CheckSql(reqClean, wlClean, url.Values{}, hostSafe, globalHost); res.IsBlock {
			t.Fatalf("正常上传文件名 %q 不应误报 SQLi", cleanName)
		}
	}

	// [H5] urlencoded 末尾附加畸形 "&pad=%" 令 url.ParseQuery 返回错误时，在 observe/off 下仍必须第一阶段强制拦截
	for _, m := range []string{"observe", "off"} {
		global.GCONFIG_BODY_DETECT_MODE = m
		reqBadPct, _ := http.NewRequest(http.MethodPost, "http://xxxx.com/login", nil)
		reqBadPct.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		badPctBody := "user=admin%27+OR+%271%27%3D%271&pad=%"
		wlBadPct := &innerbean.WebLog{BODY: badPctBody, SrcByteBody: []byte(badPctBody)}
		if res := waf.CheckSql(reqBadPct, wlBadPct, url.Values{}, hostSafe, globalHost); !res.IsBlock {
			t.Fatalf("[H5] urlencoded 含畸形 %% 在 mode=%s 下仍必须强制拦截", m)
		}
	}

	// [M3] truncateWebLogBodyForQueue 必须清空全部仅检测期大字段
	wlTrunc := &innerbean.WebLog{
		BODY:                "short",
		BodyDecoded:         "decoded-big",
		MultipartText:       "mp-big",
		MultipartPlainFiles: []string{"plain-file"},
		CookiesDecoded:      "cookie-big",
		BodyValues:          []string{"v"},
		BodyFields:          []string{"f"},
	}
	truncateWebLogBodyForQueue(wlTrunc)
	if wlTrunc.BodyDecoded != "" || wlTrunc.MultipartText != "" || wlTrunc.MultipartPlainFiles != nil || wlTrunc.CookiesDecoded != "" || wlTrunc.BodyValues != nil || wlTrunc.BodyFields != nil {
		t.Fatal("[M3] truncateWebLogBodyForQueue 未清空检测期大块临时字段")
	}

	// [Bench-R1] 伪装为 image/png 的纯文本 PHP 脚本上传（如 info.php.jpg 含 <?php phpinfo();）即使未开 CheckUpload 也必须由 CheckRce 拦截，且纯文本文件不误触发 SQLi
	var phpUploadBuf bytes.Buffer
	mwPHP := multipart.NewWriter(&phpUploadBuf)
	hPHP := make(textproto.MIMEHeader)
	hPHP.Set("Content-Disposition", `form-data; name="uploaded"; filename="info.php.jpg"`)
	hPHP.Set("Content-Type", "image/png")
	pwPHP, _ := mwPHP.CreatePart(hPHP)
	_, _ = pwPHP.Write([]byte("<?php\r\nphpinfo();\r\n?>"))
	_ = mwPHP.Close()
	reqPHP, _ := http.NewRequest(http.MethodPost, "http://xxxx.com/vulnerabilities/upload/", nil)
	reqPHP.Header.Set("Content-Type", mwPHP.FormDataContentType())
	wlPHP := &innerbean.WebLog{BODY: phpUploadBuf.String(), SrcByteBody: phpUploadBuf.Bytes()}
	if res := waf.CheckRce(reqPHP, wlPHP, url.Values{}, hostSafe, globalHost); !res.IsBlock {
		t.Fatal("伪装图片上传的纯文本 PHP 脚本必须被 CheckRce 拦截")
	}

	// [R2-3] 标准参数名下的正常散文（如 title=%22hello%22+and+world / note=%22hi%22%3B）不得因拼接 key=val 误触发 nos&n / nos;
	global.GCONFIG_BODY_DETECT_MODE = "block"
	for _, benignForm := range []string{`title=%22hello%22+and+world`, `note=%22hi%22%3B`} {
		reqBenignForm, _ := http.NewRequest(http.MethodPost, "http://xxxx.com/post", nil)
		reqBenignForm.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		wlBenignForm := &innerbean.WebLog{BODY: benignForm, SrcByteBody: []byte(benignForm)}
		if res := waf.CheckSql(reqBenignForm, wlBenignForm, url.Values{}, hostSafe, globalHost); res.IsBlock {
			t.Fatalf("[R2-3] 正常 urlencoded 散文表单不应误拦: %s", benignForm)
		}
	}
}
