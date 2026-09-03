package wafcaptcha

import (
	"strings"
	"testing"
)

// 模板里那块的真实形状
const tplWithBlock = `<html><body>
<div class="req-id">识别码：X</div>
<!--SAMWAF_CONTACT_BEGIN--><div class="contact-info"><span id="contact-label">联系管理员</span>：[[.SAMWAF_CONTACT]]</div><!--SAMWAF_CONTACT_END-->
</body></html>`

// 没填就整块不渲染。只擦占位符会留下一个带边距的空壳，看起来像页面坏了一块。
func TestInjectContact_EmptyRemovesWholeBlock(t *testing.T) {
	out := injectContact(tplWithBlock, "")
	for _, bad := range []string{"contact-info", "联系管理员", "SAMWAF_CONTACT", "[[."} {
		if strings.Contains(out, bad) {
			t.Fatalf("留空时不应残留 %q:\n%s", bad, out)
		}
	}
	// 不能顺手把别的内容删掉
	if !strings.Contains(out, "识别码") || !strings.Contains(out, "</body>") {
		t.Fatalf("删块时误伤了其它内容:\n%s", out)
	}
}

// 只填空白等同于没填
func TestInjectContact_WhitespaceOnlyTreatedAsEmpty(t *testing.T) {
	if out := injectContact(tplWithBlock, "   \n\t "); strings.Contains(out, "contact-info") {
		t.Fatalf("只填空白应按没填处理:\n%s", out)
	}
}

func TestInjectContact_FilledRendersAndDropsMarkers(t *testing.T) {
	out := injectContact(tplWithBlock, "admin@example.com")
	if !strings.Contains(out, "admin@example.com") {
		t.Fatalf("联系方式没渲染出来:\n%s", out)
	}
	if !strings.Contains(out, "contact-info") || !strings.Contains(out, "联系管理员") {
		t.Fatalf("包裹块应保留:\n%s", out)
	}
	if strings.Contains(out, "SAMWAF_CONTACT") {
		t.Fatalf("标记与占位符都应被清掉:\n%s", out)
	}
}

// 这段文本出现在**给访客看的公开页面**上，必须 HTML 转义。
// 管理端能填任意内容，不转义等于给自己留一个存储型 XSS。
func TestInjectContact_EscapesHTML(t *testing.T) {
	out := injectContact(tplWithBlock, `<img src=x onerror=alert(1)>&"'`)
	if strings.Contains(out, "<img") || strings.Contains(out, "onerror=alert(1)>") {
		t.Fatalf("联系方式必须 HTML 转义后再渲染:\n%s", out)
	}
	if !strings.Contains(out, "&lt;img") || !strings.Contains(out, "&amp;") {
		t.Fatalf("转义结果不对:\n%s", out)
	}
}

// 用户把模板改过、标记没了但占位符还在：照样要能替换
func TestInjectContact_PlaceholderOnlyTemplate(t *testing.T) {
	tpl := `<html><body><p>[[.SAMWAF_CONTACT]]</p></body></html>`
	out := injectContact(tpl, "tel:12345")
	if !strings.Contains(out, "tel:12345") || strings.Contains(out, "SAMWAF_CONTACT") {
		t.Fatalf("占位符形态没处理好:\n%s", out)
	}
	// 留空时占位符要擦掉，不能原样显示给访客
	if out := injectContact(tpl, ""); strings.Contains(out, "SAMWAF_CONTACT") {
		t.Fatalf("留空时占位符应被擦掉:\n%s", out)
	}
}

// 模板被自定义得既没标记也没占位符：兜底追加，宁可样式朴素也别把联系方式弄丢
func TestInjectContact_CustomTemplateFallbackAppends(t *testing.T) {
	tpl := `<html><body><p>hi</p></body></html>`
	out := injectContact(tpl, "admin@example.com")
	if !strings.Contains(out, "admin@example.com") {
		t.Fatalf("兜底追加没生效:\n%s", out)
	}
	if strings.Index(out, "admin@example.com") > strings.LastIndex(out, "</body>") {
		t.Fatalf("兜底块应插在 </body> 之前:\n%s", out)
	}
	// 没填时不该凭空追加东西
	if out := injectContact(tpl, ""); out != tpl {
		t.Fatalf("没填时不应改动模板:\n%s", out)
	}
}
