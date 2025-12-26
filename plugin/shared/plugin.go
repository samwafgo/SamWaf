package shared

import (
	"context"

	"SamWaf/plugin/proto"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

// Handshake 是客户端和服务器之间的握手配置
// 这必须匹配，否则插件将无法加载
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "SAMWAF_PLUGIN",
	MagicCookieValue: "samwaf-ip-filter-plugin",
}

// PluginMap 是插件类型的映射
var PluginMap = map[string]plugin.Plugin{
	"ip_filter": &IPFilterGRPCPlugin{},
}

// IPFilterGRPCPlugin 是 go-plugin 的 Plugin 实现
type IPFilterGRPCPlugin struct {
	plugin.Plugin
	Impl proto.IPFilterPluginServer
}

func (p *IPFilterGRPCPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	proto.RegisterIPFilterPluginServer(s, p.Impl)
	return nil
}

func (p *IPFilterGRPCPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return proto.NewGRPCClient(proto.NewIPFilterPluginClient(c)), nil
}
