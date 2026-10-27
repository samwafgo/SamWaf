package waf_service

import (
	resp "SamWaf/model/response"
	"SamWaf/wafdiagnose"
	"fmt"
	"strconv"
	"strings"
)

func diagnosticProbeCheck(id, title, source string, r wafdiagnose.Result) resp.WebsiteDiagnosticCheck {
	check := diagnosticCheck(id, title, "passed", "HTTP_RESPONSE", "已收到HTTP响应；请结合状态码与报文判断业务结果")
	check.Request, check.Response = r.Request, r.Response
	check.StatusCode, check.BodyTruncated = r.StatusCode, r.BodyTruncated
	check.Overview = []resp.WebsiteDiagnosticField{
		diagnosticField("证据来源", source), diagnosticField("逻辑请求URL", r.URL), diagnosticField("实际连接地址", r.ActualAddress),
		diagnosticField("HTTP Host", r.Host), diagnosticField("TLS SNI", r.SNI), diagnosticField("HTTP请求已发送", strconv.FormatBool(r.HTTPWritten)),
		diagnosticField("总耗时", fmt.Sprintf("%.1f ms", r.Timings.TotalMS)),
	}
	if r.StatusCode != 0 {
		check.Overview = append(check.Overview, diagnosticField("HTTP状态", strconv.Itoa(r.StatusCode)))
	}
	for _, attempt := range r.Attempts {
		check.Connection = append(check.Connection, diagnosticField("连接尝试", fmt.Sprintf("%s / %s / %.1f ms %s", attempt.Address, attempt.Status, attempt.MS, attempt.Reason)))
	}
	check.Connection = append(check.Connection,
		diagnosticField("DNS耗时", fmt.Sprintf("%.1f ms", r.Timings.DNSMS)), diagnosticField("TCP耗时", fmt.Sprintf("%.1f ms", r.Timings.TCPMS)),
		diagnosticField("TLS耗时", fmt.Sprintf("%.1f ms", r.Timings.TLSMS)), diagnosticField("首字节耗时", fmt.Sprintf("%.1f ms", r.Timings.FirstByteMS)))
	if r.TLS != nil {
		check.Connection = append(check.Connection, diagnosticField("TLS版本", r.TLS.Version), diagnosticField("密码套件", r.TLS.CipherSuite), diagnosticField("证书已验证", strconv.FormatBool(r.TLS.Verified)))
		for _, cert := range r.TLS.Certificates {
			check.Connection = append(check.Connection, diagnosticField("证书主体", cert.Subject), diagnosticField("证书颁发者", cert.Issuer), diagnosticField("证书SAN", strings.Join(cert.DNSNames, ", ")),
				diagnosticField("证书有效期", cert.NotBefore+" → "+cert.NotAfter), diagnosticField("证书SHA256", cert.SHA256))
		}
		if !r.TLS.Verified && r.Status == "success" {
			check.Status, check.Reason, check.Message = "warning", "TLS_NOT_VERIFIED", "按保存配置未校验证书可信性；握手完成不代表证书有效"
		}
	}
	for _, evidence := range r.Evidence {
		check.Connection = append(check.Connection, diagnosticField("检测说明", evidence))
	}
	if r.Status != "success" {
		check.Status, check.Reason = "failed", strings.ToUpper(r.Stage)
		check.Message = "检测停在" + r.Stage + "阶段：" + r.Reason
		if strings.Contains(strings.ToLower(r.Reason), "policy") || r.Stage == "validation" {
			check.Status, check.Reason = "skipped", "TARGET_POLICY"
		}
	} else if r.StatusCode >= 300 {
		check.Status = "warning"
		if r.StatusCode < 400 {
			check.Reason, check.Message = "HTTP_REDIRECT", "已收到重定向，本次不跟随；请核对Location并按需重新诊断"
		} else {
			check.Reason, check.Message = "HTTP_STATUS", "已收到HTTP "+strconv.Itoa(r.StatusCode)+"，连接已完成，请结合响应内容和访问日志检查业务或入口策略"
		}
	}
	if r.BodyTruncated {
		check.Status = "warning"
		check.Connection = append(check.Connection, diagnosticField("正文范围", "正文已截断或未完整读取，报文仅为受限预览"))
	}
	section := "backend"
	message := "检查源站进程、监听IP/端口和网络路径；HTTP Host、路径与实际连接地址应分别核对"
	if r.Stage == "tls" || check.Reason == "TLS_NOT_VERIFIED" {
		section, message = "tls", "核对源站证书有效期、SAN域名、完整证书链和运行环境信任库；此项控制回源HTTPS，不会自动忽略校验或修改配置"
	} else if id == "local_ingress" {
		section, message = "listen", "核对本站入口协议和监听；认证、防护、缓存、重定向可能提前响应，请结合访问日志确认"
	} else if id == "access_url" {
		section, message = "listen", "本结果仅代表服务器直连视角；结合用户网络核对DNS、CDN、NAT、端口映射与防火墙，不能仅凭服务器超时判断用户不可达"
	}
	check.Advice = append(check.Advice, diagnosticAdvice(check.Reason, message, section))
	return check
}
