package waf_service

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model/wafenginmodel"
	"errors"
	"net"
	"strconv"
	"strings"
)

func newHealthDialGuard(runtime ...*wafenginmodel.SafeServerMap) (func(string) error, error) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil, errors.New("读取本机源站检测地址信息失败")
	}
	localIPs := make(map[string]bool)
	for _, address := range addresses {
		if network, ok := address.(*net.IPNet); ok {
			localIPs[network.IP.String()] = true
		}
	}
	ports := map[int]bool{global.GWAF_LOCAL_SERVER_PORT: true}
	for _, listeners := range runtime {
		if listeners != nil {
			listeners.Range(func(port int, server innerbean.ServerRunTime) bool {
				if server.Status == 0 {
					ports[port] = true
				}
				return true
			})
		}
	}
	return func(address string) error {
		ipText, portText, err := net.SplitHostPort(address)
		if err != nil {
			return errors.New("实际源站地址格式不正确")
		}
		ip := net.ParseIP(strings.SplitN(ipText, "%", 2)[0])
		port, err := strconv.Atoi(portText)
		if ip == nil || err != nil {
			return errors.New("实际源站地址格式不正确")
		}
		if ports[port] && (ip.IsLoopback() || ip.IsUnspecified() || localIPs[ip.String()]) {
			return errors.New("检测目标为本机SamWaf监听端口，请填写源站地址")
		}
		return nil
	}, nil
}
