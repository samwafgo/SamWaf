package wafhttpcore

import (
	"bytes"
	"mime/multipart"
	"net/textproto"
	"testing"
)

func TestExtractMultipartFields_SkipsFileKeepsTextAndJSON(t *testing.T) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	if err := mw.WriteField("foodName", "红烧牛肉面"); err != nil {
		t.Fatal(err)
	}
	if err := mw.WriteField("encoded", "%3Cscript%3Ealert(1)%3C%2Fscript%3E"); err != nil {
		t.Fatal(err)
	}
	if err := mw.WriteField("meta", `{"remark":"1' UNION SELECT username,password FROM users--"}`); err != nil {
		t.Fatal(err)
	}
	// Issue #1084 实测触发 libinjection 指纹 s)o1 的 16 字节 JPEG 头部片段
	jpegBytes := append([]byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00},
		[]byte{0x1c, 0x16, 0x16, 0x20, 0x2c, 0x20, 0x23, 0x26, 0x27, 0x29, 0x2a, 0x29, 0x19, 0x1f, 0x2d, 0x30}...)
	fw, err := mw.CreateFormFile("upfiles", "thumb.jpg")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(jpegBytes); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}

	res := ExtractMultipartFields(mw.FormDataContentType(), buf.Bytes(), false)
	if !res.Valid {
		t.Fatalf("合法 multipart 应标记 Valid=true")
	}
	if got := res.FormValues.Get("foodName"); got != "红烧牛肉面" {
		t.Fatalf("foodName=%q, 期望 红烧牛肉面", got)
	}
	if got := res.FormValues.Get("encoded"); got != "<script>alert(1)</script>" {
		t.Fatalf("encoded 未多轮解码: %q", got)
	}
	if _, hasFile := res.FormValues["upfiles"]; hasFile {
		t.Fatalf("带 filename 的文件 part 正文不应以字段名进入 FormValues")
	}
	if len(res.JSONValues) != 1 || res.JSONFields[0] != "remark" {
		t.Fatalf("内嵌 JSON part 提取结果异常: fields=%v values=%v", res.JSONFields, res.JSONValues)
	}
}

func TestExtractMultipartFields_AdversarialH1H2H3M1(t *testing.T) {
	// [H1-1] RFC2231 boundary* 覆盖欺骗：必须拒绝免检(Valid=false)
	h1CT := "multipart/form-data; boundary=real; boundary*=utf-8''decoy"
	h1Body := []byte("--decoy\r\nContent-Disposition: form-data; name=\"ok\"\r\n\r\n1\r\n--decoy--\r\n--real\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\n1' OR '1'='1\r\n--real--\r\n")
	if r := ExtractMultipartFields(h1CT, h1Body, false); r.Valid {
		t.Fatal("[H1] 含 boundary* 歧义参数必须判 Valid=false")
	}

	// [H1-2] 终止行 --boundary-- 后尾随夹带数据：必须判 Valid=false
	epilogueBody := []byte("--b\r\nContent-Disposition: form-data; name=\"ok\"\r\n\r\n1\r\n--b--\r\n--other\r\n1' OR '1'='1")
	if r := ExtractMultipartFields("multipart/form-data; boundary=b", epilogueBody, false); r.Valid {
		t.Fatal("[H1] 终止边界后存在非空白夹带数据必须判 Valid=false")
	}

	// [H1-3] 反斜杠引号 boundary="dec\oy" + 前言 Preamble 双边界走私：必须判 Valid=false
	preambleBody := []byte("--decoy\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\n1' OR '1'='1\r\n--decoy--\r\n--dec\\oy\r\nContent-Disposition: form-data; name=\"ok\"\r\n\r\n1\r\n--dec\\oy--\r\n")
	if r := ExtractMultipartFields(`multipart/form-data; boundary="dec\oy"`, preambleBody, false); r.Valid {
		t.Fatal(`[H1-R2] 含反斜杠 boundary 或非空 Preamble 走私必须判 Valid=false`)
	}
	if r := ExtractMultipartFields("multipart/form-data; boundary=b", []byte("preamble-smuggle\r\n--b\r\nContent-Disposition: form-data; name=\"ok\"\r\n\r\n1\r\n--b--\r\n"), false); r.Valid {
		t.Fatal("[H1-R2] 首个定界符前存在非空 Preamble 必须判 Valid=false")
	}

	// [H2-3] 参数名尾部空格 "filename =a.txt"（PHP rfc1867 当作普通 $_POST 字段）：禁止按无歧义文件跳过
	trailingSpaceCD := []byte("--b\r\nContent-Disposition: form-data; name=\"id\"; filename =\"a.txt\"\r\n\r\n1' OR '1'='1\r\n--b--\r\n")
	rSpace := ExtractMultipartFields("multipart/form-data; boundary=b", trailingSpaceCD, false)
	if rSpace.Valid || len(rSpace.FormValues[MetaFormKey]) == 0 {
		t.Fatal(`[H2-R2] "filename =" 带空格存在 PHP 解析差异，必须判 Valid=false 且提取内容检测`)
	}

	// [H2-1] 引号内伪造 "; filename=a.txt"：必须识别为普通文本字段而非文件跳过
	quotedTrick := []byte("--b\r\nContent-Disposition: form-data; dummy=\"1; filename=a.txt\"; name=\"id\"\r\n\r\n1' UNION SELECT 1,2--\r\n--b--\r\n")
	rQuoted := ExtractMultipartFields("multipart/form-data; boundary=b", quotedTrick, false)
	if got := rQuoted.FormValues.Get("id"); got != "1' UNION SELECT 1,2--" {
		t.Fatalf("[H2] 引号内分号伪装 filename 必须仍按文本提取: got=%q", got)
	}

	// [H2-2] 仅带 filename*=ISO-8859-1''a.txt 无标准 filename=：Go/PHP 会当普通 POST 字段，禁止按文件跳过
	rfc2231Only := []byte("--b\r\nContent-Disposition: form-data; name=\"id\"; filename*=ISO-8859-1''a.txt\r\n\r\n1' OR '1'='1\r\n--b--\r\n")
	rStar := ExtractMultipartFields("multipart/form-data; boundary=b", rfc2231Only, false)
	if rStar.Valid {
		t.Fatal("[H2] 仅带 filename* 无标准 filename= 存在解析差异，必须判 Valid=false")
	}
	if len(rStar.FormValues[MetaFormKey]) == 0 {
		t.Fatal("[H2] 歧义 part 的内容必须进入不可排除键检测")
	}

	// [H3] Content-Transfer-Encoding: quoted-printable 软换行与 =XX 编码解码检测
	qpPart := []byte("--b\r\nContent-Disposition: form-data; name=\"id\"\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n=31=27=20UN=\r\nION=20SEL=\r\nECT=201--\r\n--b--\r\n")
	rQP := ExtractMultipartFields("multipart/form-data; boundary=b", qpPart, false)
	foundDecoded := false
	for _, v := range rQP.FormValues["id"] {
		if v == "1' UNION SELECT 1--" {
			foundDecoded = true
		}
	}
	if !foundDecoded {
		t.Fatalf("[H3] quoted-printable 文本 part 未解码: %v", rQP.FormValues["id"])
	}

	// [M1] 即使 truncatedAtBudget=true，前段塞满 >=1024 个空 part 也必须置 Valid=false
	var spam bytes.Buffer
	for i := 0; i < 1025; i++ {
		spam.WriteString("--b\r\nContent-Disposition: form-data; name=\"p\"\r\n\r\n\r\n")
	}
	spam.WriteString("--b\r\nContent-Disposition: form-data; name=\"evil\"\r\n\r\n1' OR '1'='1\r\n--b--\r\n")
	if rSpam := ExtractMultipartFields("multipart/form-data; boundary=b", spam.Bytes(), true); rSpam.Valid {
		t.Fatal("[M1] 超 1024 个 part 填充即使处于截断预算也必须判 Valid=false")
	}
}

func TestExtractMultipartFields_EmptyFilenameTreatedAsText(t *testing.T) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="id"; filename=""`)
	pw, err := mw.CreatePart(h)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = pw.Write([]byte("1' OR '1'='1"))
	_ = mw.Close()

	res := ExtractMultipartFields(mw.FormDataContentType(), buf.Bytes(), false)
	if !res.Valid {
		t.Fatal("期望 Valid=true")
	}
	if got := res.FormValues.Get("id"); got != "1' OR '1'='1" {
		t.Fatalf("空 filename 字段必须作为文本提取，实际=%q", got)
	}
}

func TestExtractMultipartFields_SpoofedHeaderOrTruncatedWindow(t *testing.T) {
	// 1) 伪造 multipart 头但正文其实是普通注入串（无匹配 boundary）→ Valid 必须为 false
	spoof := ExtractMultipartFields("multipart/form-data; boundary=fakeboundary", []byte("id=1' UNION SELECT 1,2--"), false)
	if spoof.Valid {
		t.Fatal("无匹配 boundary 的伪造报文不得标记 Valid=true")
	}

	// 2) 缺少 boundary 参数 → Valid 必须为 false
	noBoundary := ExtractMultipartFields("multipart/form-data", []byte("--x\r\n"), false)
	if noBoundary.Valid {
		t.Fatal("无 boundary 参数不得标记 Valid=true")
	}

	// 3) 大文件在 1MB 预算处正常截断：前序文本字段保留且 Valid=true
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("title", "normal-upload")
	fw, _ := mw.CreateFormFile("video", "demo.mp4")
	_, _ = fw.Write(bytes.Repeat([]byte{0x00, 0xFF, 0x27, 0x29}, 512))
	// 不调用 mw.Close() 模拟流在文件传输中途被 1MB 窗口截断
	truncatedRaw := buf.Bytes()[:len(buf.Bytes())-10]

	truncRes := ExtractMultipartFields(mw.FormDataContentType(), truncatedRaw, true)
	if !truncRes.Valid {
		t.Fatal("1MB 预算窗口截断的合法 multipart 应保持 Valid=true")
	}
	if got := truncRes.FormValues.Get("title"); got != "normal-upload" {
		t.Fatalf("截断前已出现的文本字段丢失: %q", got)
	}
}
