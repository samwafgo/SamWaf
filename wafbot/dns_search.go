package wafbot

import (
	"SamWaf/global"
	"context"
	"net"
	"time"
)

func ReverseDNSLookup(ipAddress string) ([]string, error) {
	//startTime := time.Now()

	ctx := context.Background()
	d := net.Dialer{Resolver: &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.Dial("udp", global.GWAF_RUNTIME_DNS_SERVER+":53")
		},
	}}
	//TODO 请注意此处得时间
	ctxWithTimeout, cancel := context.WithTimeout(ctx, time.Duration(global.GWAF_RUNTIME_DNS_TIMEOUT)*time.Millisecond)
	defer cancel()
	names, err := d.Resolver.LookupAddr(ctxWithTimeout, ipAddress)

	//elapsed := time.Since(startTime)

	//zlog.Debug("搜索引擎查询耗时", elapsed.String())
	if err != nil {
		return nil, err
	}
	return names, nil
}
