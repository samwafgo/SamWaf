package wafcli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

const (
	ExitOK = iota
	ExitFailed
	ExitUsage
	ExitUnavailable
	ExitAuth
	ExitNotFound
)

type Deps struct {
	ServiceControl func(action string) error
	HandoffRestart func()
	DataDir        string
}

type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string   { return e.Err.Error() }
func (e *ExitError) Unwrap() error   { return e.Err }
func fail(code int, err error) error { return &ExitError{Code: code, Err: err} }

var resultOut io.Writer
var outputFormat = "text"

func SetResultOutput(w io.Writer) { resultOut = w }
func IsAutomationCommand(args []string) bool {
	return len(args) > 1 && (args[1] == "site" || args[1] == "apikey")
}

func newRootCommand(deps Deps) *cobra.Command {
	outputFormat = "text"
	root := &cobra.Command{
		Use: "samwaf", Short: "SamWaf 服务管理与命令行工具", Example: "  samwaf --help\n  samwaf site list",
		SilenceUsage: true, SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if outputFormat != "text" && outputFormat != "json" {
				return fail(ExitUsage, errors.New("--output 必须是 text 或 json"))
			}
			return nil
		},
	}
	root.CompletionOptions.DisableDefaultCmd = true
	root.SuggestionsMinimumDistance = 2
	if resultOut != nil {
		root.SetOut(resultOut)
	} else {
		root.SetOut(os.Stdout)
	}
	root.SetErr(os.Stderr)
	root.AddGroup(
		&cobra.Group{ID: "service", Title: "服务管理:"},
		&cobra.Group{ID: "maintain", Title: "维护工具:"},
		&cobra.Group{ID: "datakey", Title: "数据密钥:"},
		&cobra.Group{ID: "auto", Title: "自动化:"},
	)
	addLegacyCommands(root, deps)
	apikey := newAPIKeyCommand()
	site := newSiteCommand()
	for _, cmd := range []*cobra.Command{apikey, site} {
		cmd.GroupID = "auto"
		if cmd == apikey {
			cmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "text", "输出格式：text 或 json")
		}
		root.AddCommand(cmd)
	}
	return root
}

func Execute(deps Deps) (code int) {
	root := newRootCommand(deps)
	// 参数解析失败时也遵守自动化命令的 JSON 输出约定。
	if IsAutomationCommand(os.Args) {
		outputFormat = requestedOutput(os.Args[2:])
	}
	defer func() {
		if recover() != nil {
			code = ExitFailed
			printError(root, errors.New("命令执行失败，请检查 CLI 日志与数据库配置"), code)
		}
	}()
	cmd, err := root.ExecuteC()
	if err == nil {
		return ExitOK
	}
	if cmd == nil {
		cmd = root
	}
	var exitErr *ExitError
	if errors.As(err, &exitErr) {
		if !errors.Is(exitErr.Err, errResultWritten) {
			printError(cmd, exitErr.Err, exitErr.Code)
		}
		return exitErr.Code
	}
	printError(cmd, fmt.Errorf("%w；使用 --help 查看用法", err), ExitUsage)
	return ExitUsage
}

func requestedOutput(args []string) string {
	format := "text"
	for i := 0; i < len(args); i++ {
		if args[i] == "--" {
			break
		}
		if (args[i] == "--output" || args[i] == "-o") && i+1 < len(args) {
			i++
			format = args[i]
		}
		if strings.HasPrefix(args[i], "--output=") {
			format = strings.TrimPrefix(args[i], "--output=")
		}
		if strings.HasPrefix(args[i], "-o") && len(args[i]) > 2 {
			format = strings.TrimPrefix(strings.TrimPrefix(args[i], "-o"), "=")
		}
	}
	return format
}

func printError(cmd *cobra.Command, err error, code int) {
	if outputFormat == "json" {
		_ = json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]interface{}{"ok": false, "error": err.Error(), "exit_code": code})
	} else {
		fmt.Fprintf(cmd.ErrOrStderr(), "error: %s\n", err)
	}
}

func writeResult(cmd *cobra.Command, result interface{}, text string) error {
	if outputFormat == "json" {
		if err := json.NewEncoder(cmd.OutOrStdout()).Encode(result); err != nil {
			return fail(ExitFailed, errors.New("输出命令结果失败"))
		}
		return nil
	}
	if _, err := fmt.Fprintln(cmd.OutOrStdout(), text); err != nil {
		return fail(ExitFailed, errors.New("输出命令结果失败"))
	}
	return nil
}

// ReportStartupFailure 按命令输出格式返回启动阶段错误。
func ReportStartupFailure() int {
	cmd := &cobra.Command{}
	if resultOut != nil {
		cmd.SetOut(resultOut)
	} else {
		cmd.SetOut(os.Stdout)
	}
	cmd.SetErr(os.Stderr)
	outputFormat = requestedOutput(os.Args[2:])
	printError(cmd, errors.New("命令初始化失败，请检查配置、文件权限与 CLI 日志"), ExitFailed)
	return ExitFailed
}
