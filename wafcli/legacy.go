package wafcli

import (
	"SamWaf/global"
	"SamWaf/supervisor"
	"SamWaf/utils"
	"SamWaf/wafdb"
	"SamWaf/wafsec"
	"SamWaf/wafupdate"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	glogger "gorm.io/gorm/logger"
)

func addLegacyCommands(root *cobra.Command, deps Deps) {
	for _, item := range []struct{ name, short string }{
		{"install", "安装为系统服务"}, {"start", "启动服务"}, {"stop", "停止服务"},
		{"restart", "重启服务"}, {"uninstall", "卸载服务"},
	} {
		action := item.name
		root.AddCommand(&cobra.Command{Use: action, Short: item.short, GroupID: "service", Args: cobra.NoArgs,
			Example: "  samwaf " + action,
			RunE: func(cmd *cobra.Command, args []string) error {
				if deps.ServiceControl == nil {
					return fail(ExitFailed, errors.New("服务控制不可用"))
				}
				if err := deps.ServiceControl(action); err != nil {
					return fail(ExitFailed, err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Samwaf has successfully executed the '%s' command.\n", action)
				return nil
			},
		})
	}
	root.AddCommand(&cobra.Command{Use: "rolling-restart", Short: "零停机滚动重启", GroupID: "service", Args: cobra.NoArgs,
		Example: "  samwaf rolling-restart",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := supervisor.TriggerUpgrade(deps.DataDir); err != nil {
				return fail(ExitFailed, fmt.Errorf("滚动重启触发失败: %w", err))
			}
			fmt.Fprintln(cmd.OutOrStdout(), "已触发零停机滚动重启，请观察日志：新 Worker 就绪后旧 Worker 将优雅排空退出。")
			return nil
		},
	})
	root.AddCommand(&cobra.Command{Use: supervisor.HandoffRestartArg, Hidden: true, Args: cobra.NoArgs,
		Example: "  samwaf " + supervisor.HandoffRestartArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			if deps.HandoffRestart == nil {
				return fail(ExitFailed, errors.New("交接重启不可用"))
			}
			deps.HandoffRestart()
			return nil
		},
	})
	for _, name := range []string{"rekey", "rekey-legacy"} {
		legacy := name == "rekey-legacy"
		root.AddCommand(&cobra.Command{Use: name, Short: map[bool]string{false: "升级遗留敏感字段的数据密钥格式", true: "将敏感字段重写回旧格式"}[legacy],
			GroupID: "datakey", Args: cobra.NoArgs, Example: "  samwaf " + name,
			RunE: func(cmd *cobra.Command, args []string) error {
				if err := wafsec.InitDataKey(utils.GetCurrentDir(), global.GCONFIG_DATA_KEY_FILE); err != nil {
					return fail(ExitFailed, fmt.Errorf("数据密钥初始化失败: %w", err))
				}
				if err := initCoreDatabase(); err != nil {
					return fail(ExitFailed, err)
				}
				if legacy {
					n := wafdb.RekeyToLegacy(global.GWAF_LOCAL_DB)
					fmt.Fprintf(cmd.OutOrStdout(), "已把 %d 行敏感字段重写回旧格式，现在可以安全降级到旧版本。\n", n)
				} else {
					n := wafdb.RekeyDataKey(global.GWAF_LOCAL_DB)
					fmt.Fprintf(cmd.OutOrStdout(), "已把 %d 行遗留敏感字段升级为当前数据密钥格式。\n", n)
					fmt.Fprintln(cmd.OutOrStdout(), "注意：本命令不做密钥轮换；请勿在替换 data_key 文件后运行它。")
				}
				return nil
			},
		})
	}
	for _, item := range []struct {
		name, short string
		run         func()
	}{
		{"resetpwd", "重置管理员密码（交互式）", wafdb.ResetAdminPwd},
		{"resetotp", "重置安全码（交互式）", wafdb.ResetAdminOTP},
	} {
		run := item.run
		root.AddCommand(&cobra.Command{Use: item.name, Short: item.short, GroupID: "maintain", Args: cobra.NoArgs,
			Example: "  samwaf " + item.name,
			RunE: func(cmd *cobra.Command, args []string) error {
				if err := initCoreDatabase(); err != nil {
					return fail(ExitFailed, err)
				}
				run()
				return nil
			},
		})
	}
	root.AddCommand(&cobra.Command{Use: "repairdb", Short: "修复损坏的数据库（交互式）", GroupID: "maintain", Args: cobra.NoArgs,
		Example: "  samwaf repairdb", RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "\n数据库修复工具\n如果您遇到数据库损坏错误，可以使用此工具尝试修复。")
			wafdb.RepairAllDatabases("")
			return nil
		},
	})
	root.AddCommand(&cobra.Command{Use: "execsql", Short: "执行 SQL 语句（交互式）", GroupID: "maintain", Args: cobra.NoArgs,
		Example: "  samwaf execsql", RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "\nSQL 执行工具\n可以在指定数据库上执行 SQL 语句")
			wafdb.ExecuteSQLCommand("")
			return nil
		},
	})
	opts := wafdb.MigrateOptions{}
	migrate := &cobra.Command{Use: "migratedb", Short: "离线迁移数据库（未指定方向时交互式）", GroupID: "maintain", Args: cobra.NoArgs,
		Example: "  samwaf migratedb\n  samwaf migratedb --from=sqlite --to=postgres --dry-run",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := wafdb.RunMigrateDB(opts); err != nil {
				return fail(ExitFailed, fmt.Errorf("迁移失败: %w", err))
			}
			return nil
		},
	}
	migrate.Flags().StringVar(&opts.From, "from", "", "迁移源：sqlite 或 mysql")
	migrate.Flags().StringVar(&opts.To, "to", "", "迁移目标：mysql 或 postgres")
	migrate.Flags().BoolVar(&opts.DryRun, "dry-run", false, "只做预估，不写入数据")
	migrate.Flags().BoolVar(&opts.Force, "force", false, "目标表已有数据时强制覆盖")
	root.AddCommand(migrate)
	root.AddCommand(&cobra.Command{Use: "rollback", Short: "回退到历史版本（交互式）", GroupID: "maintain", Args: cobra.NoArgs,
		Example: "  samwaf rollback", RunE: runRollback,
	})
}

func initCoreDatabase() (err error) {
	// GORM 默认日志器在包初始化时捕获了真实 stdout，命令行模式下不再透传数据库日志。
	glogger.Default = glogger.Default.LogMode(glogger.Silent)
	defer func() {
		if recover() != nil {
			err = errors.New("核心数据库初始化失败，请检查数据库配置与日志")
		}
	}()
	if _, err = wafdb.InitCoreDb(""); err != nil {
		return fmt.Errorf("核心数据库初始化失败: %w", err)
	}
	return nil
}

func runRollback(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	fmt.Fprintln(out, "================================================\n         SamWaf 版本回退工具\n================================================")
	fmt.Fprintf(out, "当前运行版本: %s\n\n", global.GWAF_RELEASE_VERSION)
	list, err := wafupdate.ListBackups()
	if err != nil {
		return fail(ExitFailed, fmt.Errorf("获取备份列表失败: %w", err))
	}
	if len(list) == 0 {
		return fail(ExitFailed, errors.New("没有可用的备份版本，无法回退"))
	}
	fmt.Fprintf(out, "%-4s %-15s %-22s %-10s %s\n", "序号", "版本", "备份时间", "大小(MB)", "备注")
	fmt.Fprintln(out, "------------------------------------------------------------------------")
	for i, b := range list {
		note := ""
		if b.Version == global.GWAF_RELEASE_VERSION {
			note = "[当前版本]"
		}
		fmt.Fprintf(out, "%-4d %-15s %-22s %-10.2f %s\n", i+1, b.Version, b.BackupTime.Format("2006-01-02 15:04:05"), float64(b.FileSize)/(1024*1024), note)
	}
	fmt.Fprintln(out, "------------------------------------------------------------------------")
	fmt.Fprint(out, "\n请输入要回退的序号，或输入 'q' 退出: ")
	var input string
	if _, err := fmt.Fscanln(cmd.InOrStdin(), &input); err != nil {
		return fail(ExitFailed, errors.New("读取回退序号失败"))
	}
	if input == "q" || input == "Q" {
		fmt.Fprintln(out, "已退出版本回退工具")
		return nil
	}
	idx := 0
	if _, err := fmt.Sscanf(input, "%d", &idx); err != nil || idx < 1 || idx > len(list) {
		return fail(ExitUsage, errors.New("无效的回退序号"))
	}
	target := list[idx-1]
	if target.Version == global.GWAF_RELEASE_VERSION {
		fmt.Fprintf(out, "所选版本 %s 与当前运行版本相同，无需回退\n", target.Version)
		return nil
	}
	fmt.Fprintf(out, "\n即将回退到: %s（%s）\n", target.Version, target.BackupTime.Format("2006-01-02 15:04:05"))
	fmt.Fprint(out, "确认回退？回退后需要手动重启服务 (y/n): ")
	var confirm string
	if _, err := fmt.Fscanln(cmd.InOrStdin(), &confirm); err != nil {
		return fail(ExitFailed, errors.New("读取回退确认失败"))
	}
	if confirm != "y" && confirm != "Y" {
		fmt.Fprintln(out, "已取消")
		return nil
	}
	fmt.Fprintf(out, "正在回退到版本 %s...\n", target.Version)
	if err := wafupdate.RollbackExecutable(target.Version); err != nil {
		return fail(ExitFailed, fmt.Errorf("回退失败: %w", err))
	}
	fmt.Fprintln(out, "回退成功，请重启服务 (samwaf start 或 samwaf restart)")
	return nil
}
