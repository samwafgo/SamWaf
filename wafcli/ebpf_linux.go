//go:build linux

package wafcli

import (
	"SamWaf/firewall"
	"fmt"
	"github.com/spf13/cobra"
)

// addEBPFCommand 提供无需启动数据库或管理端的本机检查/停服回退入口。
func addEBPFCommand(root *cobra.Command) {
	command := &cobra.Command{Use: "ebpf", Short: "本机 eBPF 封禁检查与回退", GroupID: "maintain"}
	command.PersistentFlags().StringVarP(&outputFormat, "output", "o", "text", "输出格式：text 或 json")
	command.AddCommand(&cobra.Command{Use: "status", Short: "检查本实例已加载的策略与丢包计数", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		status, err := firewall.BPFStatus()
		if err != nil {
			return err
		}
		return writeResult(cmd, status, fmt.Sprintf("backend=%s loaded=%v hook=%s sources=%d dropped=%d", status.Backend, status.Loaded, status.Hook, status.ActiveSources, status.DroppedPackets))
	}})
	var force bool
	detach := &cobra.Command{Use: "detach", Short: "停服后摘除本实例 eBPF 链接，保留策略账本", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		if err := firewall.DetachBPF(force); err != nil {
			return err
		}
		return writeResult(cmd, map[string]bool{"detached": true}, "本实例 eBPF 链接已摘除，策略账本保留")
	}}
	detach.Flags().BoolVar(&force, "force", false, "确认停服回退，允许摘除仍有来源表的链接")
	command.AddCommand(detach)
	root.AddCommand(command)
}
