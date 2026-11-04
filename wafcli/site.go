package wafcli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

// 测试通过工厂注入本地模拟管理端。
var siteClientFactory = newLocalClient

func newSiteCommand() *cobra.Command {
	var wait time.Duration
	cmd := &cobra.Command{Use: "site <command>", Short: "通过本机管理端管理站点", GroupID: "auto", Example: "  samwaf site apply -f site.json --wait 60s"}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return fail(ExitUsage, fmt.Errorf("unknown command %s", args[0]))
		}
		return nil
	}
	cmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "text", "输出格式：text或json")
	cmd.PersistentFlags().DurationVar(&wait, "wait", 0, "连接管理端的最长等待时间，例如60s")
	cmd.Args = func(cmd *cobra.Command, args []string) error {
		return nil
	}
	run := func(fn func(*cobra.Command, *apiClient, []string) error) func(*cobra.Command, []string) error {
		return func(c *cobra.Command, args []string) error {
			if wait < 0 {
				return fail(ExitUsage, errors.New("--wait不能为负数"))
			}
			a, err := siteClientFactory(wait)
			if err != nil {
				return err
			}
			defer a.http.CloseIdleConnections()
			return fn(c, a, args)
		}
	}
	list := &cobra.Command{Use: "list", Short: "列出全部站点", Args: cobra.NoArgs, Example: "  samwaf site list -o json", RunE: run(runSiteList)}
	get := &cobra.Command{Use: "get <code|host:port>", Short: "导出站点配置（省略密钥与自定义请求头）", Args: cobra.ExactArgs(1), Example: "  samwaf site get www.example.com:8080 > site.json", RunE: run(runSiteGet)}
	var file string
	apply := &cobra.Command{Use: "apply -f <file|->", Short: "创建或合并修改站点，相同配置跳过", Args: cobra.NoArgs, Example: "  samwaf site apply -f site.json --wait 60s\n  samwaf site apply -f - -o json", RunE: run(func(c *cobra.Command, a *apiClient, args []string) error {
		items, err := readSiteInput(file, c.InOrStdin())
		if err != nil {
			return err
		}
		return runSiteApply(c, a, items)
	})}
	apply.Flags().StringVarP(&file, "file", "f", "", "站点JSON文件，-表示标准输入")
	_ = apply.MarkFlagRequired("file")
	cmd.AddCommand(list, get, apply)
	for _, action := range []string{"delete", "start", "stop"} {
		action := action
		cmd.AddCommand(&cobra.Command{Use: action + " <code|host:port>", Short: map[string]string{"delete": "删除站点", "start": "启动站点", "stop": "停止站点"}[action], Args: cobra.ExactArgs(1), Example: "  samwaf site " + action + " www.example.com:8080", RunE: run(func(c *cobra.Command, a *apiClient, args []string) error { return runSiteAction(c, a, action, args[0]) })})
	}
	return cmd
}

func resolveSite(ctx context.Context, a *apiClient, ref string) (siteRecord, error) {
	code, host, port, err := parseSiteRef(ref)
	if err != nil {
		return nil, err
	}
	if code != "" {
		return a.detail(ctx, code)
	}
	list, err := a.list(ctx)
	if err != nil {
		return nil, err
	}
	var found string
	for _, m := range list {
		if recordString(m, "host") == host && recordInt(m, "port") == port {
			if found != "" {
				return nil, fail(ExitFailed, errors.New("站点标识不唯一，请使用code"))
			}
			found = recordString(m, "code")
		}
	}
	if found == "" {
		return nil, fail(ExitNotFound, errors.New("站点不存在"))
	}
	return a.detail(ctx, found)
}

func runSiteList(c *cobra.Command, a *apiClient, _ []string) error {
	items, err := a.list(c.Context())
	if err != nil {
		return err
	}
	summary := []siteRecord{}
	var text strings.Builder
	w := tabwriter.NewWriter(&text, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "CODE\tHOST:PORT\tREMOTE\tSTATUS\tGUARD\tNICKNAME")
	for _, m := range items {
		s := siteRecord{}
		for _, k := range []string{"code", "host", "port", "remote_host", "remote_port", "remote_ip", "start_status", "guard_status", "global_host", "nickname"} {
			if v, ok := m[k]; ok {
				s[k] = v
			}
		}
		summary = append(summary, s)
		status := "运行"
		if recordInt(m, "start_status") == 1 {
			status = "停止"
		}
		if recordInt(m, "global_host") == 1 {
			status += " [全局]"
		}
		guard := "关"
		if recordInt(m, "guard_status") == 1 {
			guard = "开"
		}
		fmt.Fprintf(w, "%s\t%s:%d\t%s:%d\t%s\t%s\t%s\n", recordString(m, "code"), recordString(m, "host"), recordInt(m, "port"), recordString(m, "remote_host"), recordInt(m, "remote_port"), status, guard, recordString(m, "nickname"))
	}
	w.Flush()
	return writeResult(c, map[string]any{"ok": true, "total": len(summary), "items": summary}, strings.TrimSuffix(text.String(), "\n"))
}

func runSiteGet(c *cobra.Command, a *apiClient, args []string) error {
	m, err := resolveSite(c.Context(), a, args[0])
	if err != nil {
		return err
	}
	site := filterEditable(m, true)
	if outputFormat == "json" {
		return writeResult(c, map[string]any{"ok": true, "site": site}, "")
	}
	enc := json.NewEncoder(c.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(site)
}

func runSiteAction(c *cobra.Command, a *apiClient, action, ref string) error {
	m, err := resolveSite(c.Context(), a, ref)
	if err != nil {
		return err
	}
	if recordInt(m, "global_host") == 1 {
		return fail(ExitFailed, errors.New("全局网站不支持通过命令行修改"))
	}
	code := recordString(m, "code")
	result := "deleted"
	path := hostAPI + "del?" + url.Values{"code": {code}}.Encode()
	if action != "delete" {
		target := 0
		if action == "stop" {
			target = 1
		}
		result = "updated"
		if recordInt(m, "start_status") == target {
			result = "unchanged"
		} else {
			path = hostAPI + "startstatus?" + url.Values{"code": {code}, "start_status": {fmt.Sprint(target)}}.Encode()
		}
	}
	if result != "unchanged" {
		if err = a.call(c.Context(), http.MethodGet, path, nil, nil); err != nil {
			return err
		}
	}
	return writeResult(c, map[string]any{"ok": true, "action": result, "code": code}, result+" "+recordString(m, "host")+":"+fmt.Sprint(recordInt(m, "port")))
}

type applyResult struct {
	Index   int      `json:"index"`
	Action  string   `json:"action"`
	Code    string   `json:"code,omitempty"`
	Host    string   `json:"host"`
	Port    int      `json:"port"`
	Changed []string `json:"changed,omitempty"`
	Error   string   `json:"error,omitempty"`
}
type plannedSite struct {
	input, cur, body siteRecord
	changed          []string
	err              error
}

func errorCode(err error) int {
	var e *ExitError
	if errors.As(err, &e) {
		return e.Code
	}
	return ExitFailed
}

func runSiteApply(c *cobra.Command, a *apiClient, items []siteRecord) error {
	plans := make([]plannedSite, len(items))
	seen := map[string]bool{}
	// 全部条目完成读取、匹配、类型与范围校验后才发送写请求。
	for i, in := range items {
		ref := recordString(in, "code")
		if ref == "" {
			ref = fmt.Sprintf("%s:%d", recordString(in, "host"), recordInt(in, "port"))
		}
		cur, err := resolveSite(c.Context(), a, ref)
		if err != nil && errorCode(err) != ExitNotFound {
			return err
		}
		identity := ref
		if cur != nil {
			identity = recordString(cur, "code")
		}
		if seen[identity] {
			return fail(ExitUsage, fmt.Errorf("第%d项：同一站点在批次中重复，请合并成一条配置", i+1))
		}
		seen[identity] = true
		p := plannedSite{input: in, cur: cur}
		if recordInt(cur, "global_host") == 1 {
			p.err = fail(ExitFailed, errors.New("全局网站不支持通过命令行修改"))
		} else {
			p.body, p.changed, err = mergeSite(cur, in)
			if err != nil {
				return fail(ExitUsage, fmt.Errorf("第%d项：%w", i+1, err))
			}
		}
		plans[i] = p
	}
	results := []applyResult{}
	firstCode := 0
	var text strings.Builder
	for i, p := range plans {
		r := applyResult{Index: i, Host: recordString(p.body, "host"), Port: recordInt(p.body, "port"), Code: recordString(p.cur, "code"), Action: "unchanged"}
		err := p.err
		if err == nil {
			if p.cur == nil {
				r.Action = "created"
				err = a.call(c.Context(), http.MethodPost, hostAPI+"add", p.body, &r.Code)
			} else if len(p.changed) > 0 {
				r.Action = "updated"
				r.Changed = p.changed
				err = a.call(c.Context(), http.MethodPost, hostAPI+"edit", p.body, nil)
			}
		}
		if err != nil {
			r.Action = "failed"
			r.Error = err.Error()
			if firstCode == 0 {
				firstCode = errorCode(err)
			}
		}
		results = append(results, r)
		fmt.Fprintf(&text, "%s %s:%d code=%s", r.Action, r.Host, r.Port, r.Code)
		if len(r.Changed) > 0 {
			fmt.Fprintf(&text, " (%s)", strings.Join(r.Changed, ", "))
		}
		if r.Error != "" {
			fmt.Fprintf(&text, " %s", r.Error)
		}
		fmt.Fprintln(&text)
		if err != nil && (errorCode(err) == ExitAuth || errorCode(err) == ExitUnavailable) {
			break
		}
	}
	result := map[string]any{"ok": firstCode == 0, "results": results, "exit_code": firstCode}
	if err := writeResult(c, result, strings.TrimSuffix(text.String(), "\n")); err != nil {
		return err
	}
	if firstCode != 0 {
		return &ExitError{Code: firstCode, Err: errResultWritten}
	}
	return nil
}

// 批量结果已输出，根命令只需返回退出码。
var errResultWritten = errors.New("批量操作包含失败条目")
