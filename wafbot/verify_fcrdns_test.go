package wafbot

import "testing"

// 后缀匹配是身份验证的第一道关，写错会把整家爬虫放过或误杀
func TestMatchAnySuffix(t *testing.T) {
	cases := []struct {
		name     string
		suffixes []string
		want     bool
	}{
		{"crawl-66-249-66-1.googlebot.com.", []string{".googlebot.com."}, true},
		{"baiduspider-116-179-32-10.crawl.baidu.com.", []string{".baidu.com.", ".baidu.jp."}, true},
		// 后缀必须带前导点，否则 evilgooglebot.com 这类同样能通过
		{"evil-googlebot.com.", []string{".googlebot.com."}, false},
		{"notbaidu.com.", []string{".baidu.com."}, false},
		{"", []string{".baidu.com."}, false},
	}
	for _, c := range cases {
		if got := matchAnySuffix(c.name, c.suffixes); got != c.want {
			t.Errorf("%q: 期望 %v，实际 %v", c.name, c.want, got)
		}
	}
}

// 非 DNS 验证的两家走公布网段，落在段内即完整验证
func TestIPRangeSpidersAreStronglyVerified(t *testing.T) {
	if r := spider360("42.236.101.5"); !r.IsNormalBot || !r.StrongVerified {
		t.Fatalf("360 公布网段内的 IP 应为完整验证，实际 %+v", r)
	}
	if r := spider360("1.2.3.4"); r.IsNormalBot || r.StrongVerified {
		t.Fatalf("360 网段外的 IP 不应通过，实际 %+v", r)
	}
	if r := byteSpider("110.249.201.5"); !r.IsNormalBot || !r.StrongVerified {
		t.Fatalf("字节公布网段内的 IP 应为完整验证，实际 %+v", r)
	}
	if r := byteSpider("1.2.3.4"); r.IsNormalBot || r.StrongVerified {
		t.Fatalf("字节网段外的 IP 不应通过，实际 %+v", r)
	}
}

// 非爬虫 UA 一次 DNS 都不该发
func TestNonSpiderUANoLookup(t *testing.T) {
	r := DetermineNormalSearch("Mozilla/5.0 (Windows NT 10.0)", "1.2.3.4")
	if r.IsBot || r.StrongVerified {
		t.Fatalf("普通浏览器 UA 不应判为爬虫，实际 %+v", r)
	}
}
