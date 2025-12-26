package main

import (
	"SamWaf/plugin/proto"
	"SamWaf/plugin/shared"

	"github.com/hashicorp/go-plugin"
)

// main 插件入口
// 使用 hashicorp/go-plugin 框架
func main() {
	// 创建插件实例
	pluginImpl := NewSimpleIPBlockerPlugin()

	// 使用 go-plugin 提供服务
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: shared.Handshake,
		Plugins: map[string]plugin.Plugin{
			"ip_filter": &shared.IPFilterGRPCPlugin{
				Impl: &proto.GRPCServer{
					Impl: pluginImpl,
				},
			},
		},
		// 使用 gRPC 协议
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
