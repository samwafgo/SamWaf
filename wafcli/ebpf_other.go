//go:build !linux

package wafcli

import "github.com/spf13/cobra"

// addEBPFCommand 非 Linux 平台不注册内核专用维护命令。
func addEBPFCommand(root *cobra.Command) {}
