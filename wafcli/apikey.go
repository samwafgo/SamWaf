package wafcli

import (
	"SamWaf/global"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"SamWaf/wafsec"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func newAPIKeyCommand() *cobra.Command {
	root := &cobra.Command{Use: "apikey", Short: "本机命令行 API Key", Example: "  samwaf apikey init"}
	var rotate, show bool
	initCmd := &cobra.Command{Use: "init", Short: "创建或复用本机命令行 Key", Args: cobra.NoArgs,
		Example: "  samwaf apikey init\n  samwaf apikey init --rotate\n  samwaf apikey init --show",
		RunE: func(cmd *cobra.Command, args []string) error {
			keyPath := filepath.Clean(filepath.Join(utils.GetCurrentDir(), "data", ".keys", "cli_api_key"))
			if err := prepareKeyDirectory(keyPath); err != nil {
				return fail(ExitFailed, fmt.Errorf("准备 Key 文件目录失败: %w", err))
			}
			if err := wafsec.InitDataKey(utils.GetCurrentDir(), global.GCONFIG_DATA_KEY_FILE); err != nil {
				return fail(ExitFailed, fmt.Errorf("数据密钥初始化失败: %w", err))
			}
			if err := initCoreDatabase(); err != nil {
				return fail(ExitFailed, err)
			}
			var key, action string
			var err error
			for attempt := 0; ; attempt++ {
				key, action, err = waf_service.WafOPlatformKeyServiceApp.EnsureLocalOnlyKey(rotate)
				if err == nil {
					break
				}
				if attempt >= 5 || !strings.Contains(strings.ToLower(err.Error()), "database is locked") {
					return fail(ExitFailed, fmt.Errorf("初始化本机 Key 失败: %w", err))
				}
				time.Sleep(500 * time.Millisecond)
			}
			if err := writeKeyFile(keyPath, key); err != nil {
				return fail(ExitFailed, fmt.Errorf("写入 Key 文件失败: %w", err))
			}
			if show {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), key); err != nil {
					return fail(ExitFailed, errors.New("输出 Key 失败"))
				}
				return nil
			}
			label := map[string]string{"created": "创建", "reused": "复用", "rotated": "更换"}[action]
			return writeResult(cmd, map[string]interface{}{"ok": true, "action": action, "key_file": keyPath},
				fmt.Sprintf("本机命令行 Key 已%s，已写入 %s（仅限本机调用，不受开放平台开关影响）", label, keyPath))
		},
	}
	initCmd.Flags().BoolVar(&rotate, "rotate", false, "更换本机 Key，使旧 Key 失效")
	initCmd.Flags().BoolVar(&show, "show", false, "仅输出 Key 本身")
	root.AddCommand(initCmd)
	return root
}

// rejectKeySymlinks 检查完整路径，允许尚不存在的目录与文件。
func rejectKeySymlinks(path string) error {
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return err
	}
	for current := abs; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return errors.New("Key 路径不能包含符号链接")
			}
			if current == abs && !info.Mode().IsRegular() {
				return errors.New("Key 文件必须是普通文件")
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		if parent := filepath.Dir(current); parent == current {
			break
		}
	}
	return nil
}

func prepareKeyDirectory(path string) error {
	if err := rejectKeySymlinks(path); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := rejectKeySymlinks(path); err != nil {
		return err
	}
	return os.Chmod(dir, 0700)
}

func writeKeyFile(path, key string) error {
	if err := prepareKeyDirectory(path); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), "cli_api_key-*.tmp")
	if err != nil {
		return err
	}
	temp := file.Name()
	defer os.Remove(temp)
	defer file.Close()
	if err := file.Chmod(0600); err != nil {
		return err
	}
	if _, err := file.WriteString(key + "\n"); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := rejectKeySymlinks(path); err != nil {
		return err
	}
	return os.Rename(temp, path)
}
