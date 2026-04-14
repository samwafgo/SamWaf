// 集成测试：验证所有带 @Router 注解的 API 路由路径是否可达（返回非 404）
// 运行前请确保 SamWaf 服务已启动。
//
// 运行命令：
//
//	go test -v -run TestAllRoutes ./test/
//
// 如需跳过集成测试，加 -short 参数：
//
//	go test -short ./test/
package apicheck

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// 配置入口：修改这里即可
// ─────────────────────────────────────────────────────────────────────────────

const (
	baseURL = "http://127.0.0.1:26666" // 服务地址
	sk      = "1111111"                // X-Token 登录令牌，按实际值修改
)

// ─────────────────────────────────────────────────────────────────────────────
// 路由清单（与 @Router 注解保持一致）
// ─────────────────────────────────────────────────────────────────────────────

type route struct {
	method string
	path   string
	desc   string
}

var registeredRoutes = []route{
	// ── IP 白名单 ──────────────────────────────────────────────────
	{"POST", "/api/v1/wafhost/ipwhite/add", "新增IP白名单"},
	{"GET", "/api/v1/wafhost/ipwhite/detail", "获取IP白名单详情"},
	{"POST", "/api/v1/wafhost/ipwhite/list", "获取IP白名单列表"},
	{"GET", "/api/v1/wafhost/ipwhite/del", "删除IP白名单"},
	{"POST", "/api/v1/wafhost/ipwhite/edit", "编辑IP白名单"},

	// ── URL 白名单 ─────────────────────────────────────────────────
	{"POST", "/api/v1/wafhost/urlwhite/add", "新增URL白名单"},
	{"GET", "/api/v1/wafhost/urlwhite/detail", "获取URL白名单详情"},
	{"POST", "/api/v1/wafhost/urlwhite/list", "获取URL白名单列表"},
	{"GET", "/api/v1/wafhost/urlwhite/del", "删除URL白名单"},
	{"POST", "/api/v1/wafhost/urlwhite/edit", "编辑URL白名单"},

	// ── IP 黑名单 ──────────────────────────────────────────────────
	{"POST", "/api/v1/wafhost/ipblock/add", "新增IP黑名单"},
	{"GET", "/api/v1/wafhost/ipblock/detail", "获取IP黑名单详情"},
	{"POST", "/api/v1/wafhost/ipblock/list", "获取IP黑名单列表"},
	{"GET", "/api/v1/wafhost/ipblock/del", "删除IP黑名单"},
	{"POST", "/api/v1/wafhost/ipblock/edit", "编辑IP黑名单"},

	// ── URL 黑名单 ─────────────────────────────────────────────────
	{"POST", "/api/v1/wafhost/urlblock/add", "新增URL黑名单"},
	{"GET", "/api/v1/wafhost/urlblock/detail", "获取URL黑名单详情"},
	{"POST", "/api/v1/wafhost/urlblock/list", "获取URL黑名单列表"},
	{"GET", "/api/v1/wafhost/urlblock/del", "删除URL黑名单"},
	{"POST", "/api/v1/wafhost/urlblock/edit", "编辑URL黑名单"},

	// ── Anti-CC ────────────────────────────────────────────────────
	{"POST", "/api/v1/wafhost/anticc/add", "新增Anti-CC规则"},
	{"GET", "/api/v1/wafhost/anticc/detail", "获取Anti-CC规则详情"},
	{"POST", "/api/v1/wafhost/anticc/list", "获取Anti-CC规则列表"},
	{"GET", "/api/v1/wafhost/anticc/del", "删除Anti-CC规则"},
	{"POST", "/api/v1/wafhost/anticc/edit", "编辑Anti-CC规则"},

	// ── IP 失败封禁 ────────────────────────────────────────────────
	{"GET", "/api/v1/wafhost/ipfailure/config", "获取IP失败封禁配置"},
	{"POST", "/api/v1/wafhost/ipfailure/config", "设置IP失败封禁配置"},
	{"GET", "/api/v1/wafhost/ipfailure/baniplist", "获取IP失败封禁列表"},

	// ── 防火墙 IP 封禁 ─────────────────────────────────────────────
	{"POST", "/api/v1/firewall/ipblock/add", "新增防火墙IP封禁"},
	{"POST", "/api/v1/firewall/ipblock/list", "获取防火墙IP封禁列表"},
	{"GET", "/api/v1/firewall/ipblock/del", "删除防火墙IP封禁"},
	{"POST", "/api/v1/firewall/ipblock/edit", "编辑防火墙IP封禁"},

	// ── WAF 规则 ───────────────────────────────────────────────────
	{"POST", "/api/v1/wafhost/rule/add", "新增WAF规则"},
	{"GET", "/api/v1/wafhost/rule/detail", "获取WAF规则详情"},
	{"POST", "/api/v1/wafhost/rule/list", "获取WAF规则列表"},
	{"GET", "/api/v1/wafhost/rule/del", "删除WAF规则"},
	{"POST", "/api/v1/wafhost/rule/edit", "编辑WAF规则"},
	{"GET", "/api/v1/wafhost/rule/rulestatus", "修改WAF规则状态"},

	// ── 敏感词 ─────────────────────────────────────────────────────
	{"POST", "/api/v1/wafhost/sensitive/add", "新增敏感词"},
	{"GET", "/api/v1/wafhost/sensitive/detail", "获取敏感词详情"},
	{"POST", "/api/v1/wafhost/sensitive/list", "获取敏感词列表"},
	{"GET", "/api/v1/wafhost/sensitive/del", "删除敏感词"},
	{"POST", "/api/v1/wafhost/sensitive/edit", "编辑敏感词"},

	// ── 缓存规则 ───────────────────────────────────────────────────
	{"POST", "/api/v1/wafhost/cacherule/add", "新增缓存规则"},
	{"GET", "/api/v1/wafhost/cacherule/detail", "获取缓存规则详情"},
	{"POST", "/api/v1/wafhost/cacherule/list", "获取缓存规则列表"},
	{"GET", "/api/v1/wafhost/cacherule/del", "删除缓存规则"},
	{"POST", "/api/v1/wafhost/cacherule/edit", "编辑缓存规则"},

	// ── 负载均衡 ───────────────────────────────────────────────────
	{"POST", "/api/v1/wafhost/loadbalance/add", "新增负载均衡"},
	{"GET", "/api/v1/wafhost/loadbalance/detail", "获取负载均衡详情"},
	{"POST", "/api/v1/wafhost/loadbalance/list", "获取负载均衡列表"},
	{"GET", "/api/v1/wafhost/loadbalance/del", "删除负载均衡"},
	{"POST", "/api/v1/wafhost/loadbalance/edit", "编辑负载均衡"},

	// ── 一键修改 ───────────────────────────────────────────────────
	{"GET", "/api/v1/wafhost/onekeymod/detail", "获取一键修改详情"},
	{"POST", "/api/v1/wafhost/onekeymod/list", "获取一键修改列表"},
	{"GET", "/api/v1/wafhost/onekeymod/del", "删除一键修改"},
	{"POST", "/api/v1/wafhost/onekeymod/doModify", "执行一键修改"},
	{"GET", "/api/v1/wafhost/onekeymod/restore", "还原一键修改"},

	// ── 任务管理 ───────────────────────────────────────────────────
	{"POST", "/api/v1/wafhost/task/add", "新增任务"},
	{"GET", "/api/v1/wafhost/task/detail", "获取任务详情"},
	{"POST", "/api/v1/wafhost/task/list", "获取任务列表"},
	{"GET", "/api/v1/wafhost/task/del", "删除任务"},
	{"POST", "/api/v1/wafhost/task/edit", "编辑任务"},
	{"GET", "/api/v1/wafhost/task/manual_exec", "手动执行任务"},
	{"GET", "/api/v1/wafhost/task/log", "获取任务日志"},
	{"GET", "/api/v1/wafhost/task/log/clear", "清空任务日志"},

	// ── 数据保留策略 ───────────────────────────────────────────────
	{"POST", "/api/v1/wafhost/dataretention/list", "获取数据保留策略列表"},
	{"GET", "/api/v1/wafhost/dataretention/detail", "获取数据保留策略详情"},
	{"POST", "/api/v1/wafhost/dataretention/edit", "编辑数据保留策略"},

	// ── 私有信息 ───────────────────────────────────────────────────
	{"POST", "/api/v1/wafhost/privateinfo/add", "新增私有信息"},
	{"GET", "/api/v1/wafhost/privateinfo/detail", "获取私有信息详情"},
	{"POST", "/api/v1/wafhost/privateinfo/list", "获取私有信息列表"},
	{"GET", "/api/v1/wafhost/privateinfo/del", "删除私有信息"},
	{"POST", "/api/v1/wafhost/privateinfo/edit", "编辑私有信息"},

	// ── 私有分组 ───────────────────────────────────────────────────
	{"POST", "/api/v1/wafhost/privategroup/add", "新增私有分组"},
	{"GET", "/api/v1/wafhost/privategroup/detail", "获取私有分组详情"},
	{"POST", "/api/v1/wafhost/privategroup/list", "获取私有分组列表"},
	{"POST", "/api/v1/wafhost/privategroup/listbybelongcloud", "按云获取私有分组列表"},
	{"GET", "/api/v1/wafhost/privategroup/del", "删除私有分组"},
	{"POST", "/api/v1/wafhost/privategroup/edit", "编辑私有分组"},

	// ── 网站管理 ───────────────────────────────────────────────────
	{"POST", "/api/v1/wafhost/host/add", "新增站点"},
	{"GET", "/api/v1/wafhost/host/detail", "获取站点详情"},
	{"POST", "/api/v1/wafhost/host/list", "获取站点列表"},
	{"GET", "/api/v1/wafhost/host/del", "删除站点"},
	{"POST", "/api/v1/wafhost/host/edit", "编辑站点"},
	{"GET", "/api/v1/wafhost/host/guardstatus", "修改防护状态"},
	{"GET", "/api/v1/wafhost/host/startstatus", "修改启动状态"},

	// ── SSL 证书 ───────────────────────────────────────────────────
	{"POST", "/api/v1/sslconfig/add", "新增SSL证书"},
	{"GET", "/api/v1/sslconfig/detail", "获取SSL证书详情"},
	{"POST", "/api/v1/sslconfig/list", "获取SSL证书列表"},
	{"GET", "/api/v1/sslconfig/del", "删除SSL证书"},
	{"POST", "/api/v1/sslconfig/edit", "编辑SSL证书"},

	// ── SSL 订单 ───────────────────────────────────────────────────
	{"POST", "/api/v1/wafhost/sslorder/add", "新增SSL订单"},
	{"GET", "/api/v1/wafhost/sslorder/detail", "获取SSL订单详情"},
	{"POST", "/api/v1/wafhost/sslorder/list", "获取SSL订单列表"},
	{"GET", "/api/v1/wafhost/sslorder/del", "删除SSL订单"},
	{"POST", "/api/v1/wafhost/sslorder/edit", "编辑SSL订单"},

	// ── SSL 到期监控 ───────────────────────────────────────────────
	{"POST", "/api/v1/wafhost/sslexpire/add", "新增SSL到期监控"},
	{"GET", "/api/v1/wafhost/sslexpire/detail", "获取SSL到期监控详情"},
	{"POST", "/api/v1/wafhost/sslexpire/list", "获取SSL到期监控列表"},
	{"GET", "/api/v1/wafhost/sslexpire/del", "删除SSL到期监控"},
	{"POST", "/api/v1/wafhost/sslexpire/edit", "编辑SSL到期监控"},
	{"GET", "/api/v1/wafhost/sslexpire/nowcheck", "立即检测SSL到期"},
	{"GET", "/api/v1/wafhost/sslexpire/sync_host", "从站点同步SSL监控"},

	// ── 隧道 ───────────────────────────────────────────────────────
	{"POST", "/api/v1/tunnel/tunnel/add", "新增隧道"},
	{"GET", "/api/v1/tunnel/tunnel/detail", "获取隧道详情"},
	{"POST", "/api/v1/tunnel/tunnel/list", "获取隧道列表"},
	{"GET", "/api/v1/tunnel/tunnel/del", "删除隧道"},
	{"POST", "/api/v1/tunnel/tunnel/edit", "编辑隧道"},
	{"GET", "/api/v1/tunnel/tunnel/connections", "获取隧道连接数"},

	// ── 通知渠道 ───────────────────────────────────────────────────
	{"POST", "/api/v1/notify/channel/add", "新增通知渠道"},
	{"GET", "/api/v1/notify/channel/detail", "获取通知渠道详情"},
	{"POST", "/api/v1/notify/channel/list", "获取通知渠道列表"},
	{"GET", "/api/v1/notify/channel/del", "删除通知渠道"},
	{"POST", "/api/v1/notify/channel/edit", "编辑通知渠道"},

	// ── 通知订阅 ───────────────────────────────────────────────────
	{"POST", "/api/v1/notify/subscription/add", "新增通知订阅"},
	{"POST", "/api/v1/notify/subscription/list", "获取通知订阅列表"},
	{"GET", "/api/v1/notify/subscription/del", "删除通知订阅"},

	// ── 通知日志 ───────────────────────────────────────────────────
	{"POST", "/api/v1/notify/log/list", "获取通知日志列表"},
	{"GET", "/api/v1/notify/log/detail", "获取通知日志详情"},
	{"GET", "/api/v1/notify/log/del", "删除通知日志"},

	// ── VIP 配置 ───────────────────────────────────────────────────
	{"POST", "/api/v1/vipconfig/updateIpWhitelist", "更新管理IP白名单"},
	{"GET", "/api/v1/vipconfig/getIpWhitelist", "获取管理IP白名单"},
	{"POST", "/api/v1/vipconfig/updateSslEnable", "更新SSL启用状态"},
	{"GET", "/api/v1/vipconfig/getSslStatus", "获取SSL启用状态"},
	{"GET", "/api/v1/vipconfig/getSecurityEntry", "获取安全入口"},
	{"POST", "/api/v1/vipconfig/updateSecurityEntry", "更新安全入口"},

	// ── 系统配置 ───────────────────────────────────────────────────
	{"POST", "/api/v1/systemconfig/list", "获取系统配置列表"},
	{"POST", "/api/v1/systemconfig/edit", "更新系统配置"},
	{"POST", "/api/v1/systemconfig/editByItem", "通过item更新系统配置"},

	// ── 系统监控 ───────────────────────────────────────────────────
	{"GET", "/api/v1/monitor/system_info", "获取系统监控信息"},

	// ── 统计数据 ───────────────────────────────────────────────────
	{"GET", "/api/v1/wafstatsumday", "获取今日访问统计"},
	{"GET", "/api/v1/wafstatsumdayrange", "按日期范围统计访问量"},
	{"GET", "/api/v1/wafstatsumdaytopiprange", "统计攻击IP排行"},
	{"GET", "/api/v1/statsysinfo", "获取首页系统基本信息"},
	{"GET", "/api/v1/statrumtimesysinfo", "获取运行时系统基本信息"},
	{"GET", "/api/v1/wafstatsiteoverview", "站点综合概览统计"},
	{"GET", "/api/v1/wafstatsitedetail", "站点详情趋势查询"},

	// ── 系统信息 ───────────────────────────────────────────────────
	{"GET", "/api/v1/sysinfo/version", "获取版本信息"},

	// ── 系统日志 ───────────────────────────────────────────────────
	{"GET", "/api/v1/sys_log/list", "获取系统日志列表"},
	{"GET", "/api/v1/sys_log/detail", "获取系统日志详情"},

	// ── 攻击日志 ───────────────────────────────────────────────────
	{"POST", "/api/v1/waflog/attack/list", "获取攻击日志列表"},
	{"GET", "/api/v1/waflog/attack/detail", "获取攻击日志详情"},

	// ── 日志文件 ───────────────────────────────────────────────────
	{"GET", "/api/v1/logfilewrite/preview", "预览日志文件"},
	{"GET", "/api/v1/logfilewrite/currentfile", "获取当前日志文件"},
	{"GET", "/api/v1/logfilewrite/backupfiles", "获取备份日志文件列表"},
	{"POST", "/api/v1/logfilewrite/clear", "清空日志文件"},
	{"GET", "/api/v1/logfilewrite/variables", "获取日志变量"},

	// ── WAF 引擎 ───────────────────────────────────────────────────
	{"GET", "/api/v1/resetWAF", "重启WAF引擎"},
}

// ─────────────────────────────────────────────────────────────────────────────

var httpClient = &http.Client{Timeout: 10 * time.Second}

// sendRequest 发起请求，GET/POST 均带 X-Token，POST body 为空 JSON
func sendRequest(method, url string) (*http.Response, error) {
	var body *bytes.Reader
	if method == "POST" {
		body = bytes.NewReader([]byte("{}"))
	} else {
		body = bytes.NewReader(nil)
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", sk)
	req.Header.Set("Content-Type", "application/json")
	return httpClient.Do(req)
}

// TestAllRoutes 逐条验证 @Router 中的路由是否注册可达（非 404）
func TestAllRoutes(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过集成测试（-short 模式）")
	}

	type result struct {
		route
		status int
		err    string
		passed bool
	}

	results := make([]result, 0, len(registeredRoutes))
	failCount := 0

	for _, r := range registeredRoutes {
		url := baseURL + r.path
		resp, err := sendRequest(r.method, url)

		res := result{route: r}
		if err != nil {
			res.err = err.Error()
			res.passed = false
		} else {
			resp.Body.Close()
			res.status = resp.StatusCode
			res.passed = resp.StatusCode != http.StatusNotFound
		}
		results = append(results, res)

		if !res.passed {
			failCount++
		}
	}

	// ── 打印汇总 ──────────────────────────────────────────────────
	t.Log(strings.Repeat("─", 80))
	t.Logf("%-6s %-50s %-6s %s", "方法", "路径", "状态", "描述")
	t.Log(strings.Repeat("─", 80))
	for _, res := range results {
		statusStr := fmt.Sprintf("%d", res.status)
		if res.err != "" {
			statusStr = "ERR"
		}
		mark := "✓"
		if !res.passed {
			mark = "✗"
		}
		t.Logf("%s %-6s %-50s %-6s %s", mark, res.method, res.path, statusStr, res.desc)
	}
	t.Log(strings.Repeat("─", 80))
	t.Logf("合计 %d 条，通过 %d 条，失败 %d 条", len(results), len(results)-failCount, failCount)

	if failCount > 0 {
		t.Fail()
	}
}

// TestSingleRoute 调试单条路由时使用（修改下面的 method/path 后运行）
func TestSingleRoute(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过集成测试（-short 模式）")
	}

	method := "GET"
	path := "/api/v1/sysinfo/version"

	url := baseURL + path
	resp, err := sendRequest(method, url)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	t.Logf("%s %s → HTTP %d", method, url, resp.StatusCode)
	if resp.StatusCode == http.StatusNotFound {
		t.Errorf("路由不存在 (404)")
	}
}
