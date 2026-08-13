package ssl

import (
	"SamWaf/common/zlog"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/providers/http/webroot"
)

// 证书校验过程的日志前缀。全流程（lego 内部日志、文件校验、DNS 校验、IP 证书）
// 统一用同一个前缀，用户搜一个词就能把整条链路捞出来。
const acmeLogPrefix = "ACME证书: "

// ── HTTP-01（文件校验）─────────────────────────────────────────────

// loggingWebrootProvider 给 lego 的 webroot provider 包一层日志。
//
// 为什么要包这一层：HTTP-01 失败时用户手里只有 CA 回的一句
// "Invalid response from http://xxx/.well-known/acme-challenge/<token>: 404"，
// 至于挑战文件到底写没写、写到哪个目录去了，一点线索都没有。
//
// 这条信息在**申请侧**，与"校验请求有没有打到 WAF"无关，
// 是整条链路里唯一一个不管后面哪一环出问题都一定拿得到的事实，
// 所以它决定了排查方向：文件没生成 → 查申请侧；文件生成了 → 查请求侧。
//
// 另外挑战文件的生命周期只有几秒（校验结束 CleanUp 就删），
// 用户去目录里翻基本什么都看不到，只能靠日志留痕。
type loggingWebrootProvider struct {
	inner *webroot.HTTPProvider
	root  string
}

// newLoggingWebrootProvider 构造带日志的 webroot provider，申请与续期共用。
func newLoggingWebrootProvider(root string) (*loggingWebrootProvider, error) {
	inner, err := webroot.NewHTTPProvider(root)
	if err != nil {
		// lego 这里只会在目录不存在时报错，但它的错误原文不带路径，
		// 用户看到 "webroot path does not exist" 也不知道该去建哪个目录。
		zlog.Error(fmt.Sprintf("%s文件校验目录不可用 路径=%s 错误=%v", acmeLogPrefix, root, err))
		return nil, err
	}
	return &loggingWebrootProvider{inner: inner, root: root}, nil
}

// challengeFilePath 挑战文件的绝对路径，拼法与 lego 内部保持一致。
func (p *loggingWebrootProvider) challengeFilePath(token string) string {
	return filepath.Join(p.root, http01.ChallengePath(token))
}

// Present 写挑战文件（CA 校验前）。
func (p *loggingWebrootProvider) Present(domain, token, keyAuth string) error {
	path := p.challengeFilePath(token)

	if err := p.inner.Present(domain, token, keyAuth); err != nil {
		zlog.Error(fmt.Sprintf("%s文件校验-挑战文件写入失败 域名=%s 路径=%s 错误=%v", acmeLogPrefix, domain, path, err))
		return err
	}

	// 写完立刻回读一次：WriteFile 返回成功不等于文件真的躺在那儿
	// （杀软拦截、权限、同步工具改写目录都碰到过），
	// 而"文件在不在"正是这里唯一要回答的问题，值得多花一次 stat。
	readBack := "否"
	var size int64 = -1
	if st, statErr := os.Stat(path); statErr == nil {
		readBack = "是"
		size = st.Size()
	}

	zlog.Info(fmt.Sprintf("%s文件校验-挑战文件已生成 域名=%s 路径=%s 可回读=%s 实际大小=%d 期望大小=%d CA将访问=http://%s%s",
		acmeLogPrefix, domain, path, readBack, size, len(keyAuth), domain, http01.ChallengePath(token)))
	return nil
}

// CleanUp 删挑战文件（CA 校验后，无论成败都会调用）。
func (p *loggingWebrootProvider) CleanUp(domain, token, keyAuth string) error {
	path := p.challengeFilePath(token)

	if err := p.inner.CleanUp(domain, token, keyAuth); err != nil {
		// 删不掉只是留下一个残留文件，不该影响签发结果，所以只告警不升级成错误。
		// 但要留痕：残留文件会让下一次同名 token 的排查产生误判。
		zlog.Warn(fmt.Sprintf("%s文件校验-挑战文件清理失败 域名=%s 路径=%s 错误=%v", acmeLogPrefix, domain, path, err))
		return err
	}

	zlog.Info(fmt.Sprintf("%s文件校验-挑战文件已清理 域名=%s 路径=%s", acmeLogPrefix, domain, path))
	return nil
}

// ── DNS-01（DNS 校验）──────────────────────────────────────────────

// loggingDNSProvider 给各家 DNS 厂商的 provider 包一层日志。
//
// DNS 方式失败时用户看到的通常只有一句超时，而真正要确认的是三件事：
// 记录写没写进去、写的是哪条 FQDN、值是什么。有了它，用户可以直接拿日志里的
// FQDN 和记录值去自己的 DNS 控制台或 dig 一下对照，不用再猜。
//
// 特别是 CNAME 委托的场景：日志里 FQDN 与实际生效的 EffectiveFQDN 不一致时，
// 一眼就能看出记录被委托到了别处，这类问题光看超时报错永远查不出来。
type loggingDNSProvider struct {
	inner   challenge.Provider
	dnsName string // 渠道名，如 alidns / tencentcloud
}

func (p *loggingDNSProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	if err := p.inner.Present(domain, token, keyAuth); err != nil {
		zlog.Error(fmt.Sprintf("%sDNS校验-记录写入失败 域名=%s 渠道=%s 记录=TXT %s 记录值=%s 错误=%v",
			acmeLogPrefix, domain, p.dnsName, info.FQDN, info.Value, err))
		return err
	}

	cnameTip := ""
	if info.EffectiveFQDN != info.FQDN {
		cnameTip = fmt.Sprintf(" 实际生效FQDN=%s(存在CNAME委托)", info.EffectiveFQDN)
	}
	zlog.Info(fmt.Sprintf("%sDNS校验-记录已写入 域名=%s 渠道=%s 记录=TXT %s 记录值=%s%s 提示=接下来等待DNS传播，可用 dig txt %s 自行核对",
		acmeLogPrefix, domain, p.dnsName, info.FQDN, info.Value, cnameTip, info.FQDN))
	return nil
}

func (p *loggingDNSProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	if err := p.inner.CleanUp(domain, token, keyAuth); err != nil {
		// 同 HTTP-01：删不掉只是留下一条残留 TXT，不该影响签发，但必须留痕，
		// 否则下次申请时控制台里堆着多条 _acme-challenge 记录，排查会被带偏。
		zlog.Warn(fmt.Sprintf("%sDNS校验-记录清理失败 域名=%s 渠道=%s 记录=TXT %s 错误=%v",
			acmeLogPrefix, domain, p.dnsName, info.FQDN, err))
		return err
	}

	zlog.Info(fmt.Sprintf("%sDNS校验-记录已清理 域名=%s 渠道=%s 记录=TXT %s", acmeLogPrefix, domain, p.dnsName, info.FQDN))
	return nil
}

// loggingDNSProviderTimeout 用于内层 provider 自己实现了 Timeout 的情况。
//
// lego 是靠类型断言判断 provider 有没有 Timeout 的（challenge.ProviderTimeout）。
// 包一层却不把 Timeout 透出去，各家厂商自定义的传播等待时间就会被悄悄换成
// 默认的 60s/2s —— 这类退化不会报错，只会表现为"偶尔续期失败"，极难查。
type loggingDNSProviderTimeout struct {
	*loggingDNSProvider
	timeout challenge.ProviderTimeout
}

func (p *loggingDNSProviderTimeout) Timeout() (time.Duration, time.Duration) {
	return p.timeout.Timeout()
}

// newLoggingDNSProvider 按内层 provider 的能力返回对应的包装类型。
func newLoggingDNSProvider(inner challenge.Provider, dnsName string) challenge.Provider {
	base := &loggingDNSProvider{inner: inner, dnsName: dnsName}
	if t, ok := inner.(challenge.ProviderTimeout); ok {
		timeout, interval := t.Timeout()
		zlog.Info(fmt.Sprintf("%sDNS校验-使用渠道 %s 自带的传播等待参数 超时=%v 间隔=%v", acmeLogPrefix, dnsName, timeout, interval))
		return &loggingDNSProviderTimeout{loggingDNSProvider: base, timeout: t}
	}
	zlog.Info(fmt.Sprintf("%sDNS校验-渠道 %s 未提供传播等待参数，使用lego默认值", acmeLogPrefix, dnsName))
	return base
}
