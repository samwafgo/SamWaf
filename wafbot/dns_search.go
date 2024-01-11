package wafbot

import (
	"SamWaf/global"
	"context"
	"fmt"
	"net"
	"time"
)

func ReverseDNSLookup(ipAddress string) ([]string, error) {
	startTime := time.Now()

	ctx := context.Background()
	d := net.Dialer{Resolver: &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.Dial("udp", global.GWAF_RUNTIME_DNS_SERVER+":53")
		},
	}}
	ctxWithTimeout, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	names, err := d.Resolver.LookupAddr(ctxWithTimeout, ipAddress)

	elapsed := time.Since(startTime)

	fmt.Println(elapsed)
	if err != nil {
		return nil, fmt.Errorf("逆向 DNS 查询失败: %s", err)
	}

	if len(names) == 0 {
		return nil, fmt.Errorf("未找到与该 IP 地址关联的域名")
	}

	return names, nil
}
