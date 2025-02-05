package wafbot

import (
	"fmt"
	"testing"
)

func TestReverseGoogleDNSLookup(t *testing.T) {
	lookup, err := ReverseDNSLookup("66.249.64.174")
	if err == nil {
		for _, s := range lookup {
			fmt.Println(s)
		}
	} else {
		fmt.Println(err)
	}
}

func TestReverseDNSLookup(t *testing.T) {
	lookup, err := ReverseDNSLookup("3.3.77.3")
	if err == nil {
		for _, s := range lookup {
			fmt.Println(s)
		}
	} else {
		fmt.Println("错误:", err)
	}
}

func BenchmarkReverseDNSLookup(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := ReverseDNSLookup("66.249.64.174")
		if err != nil {
			fmt.Println(err)
		}
		//逆向 DNS 查询失败: lookup 174.64.249.66.in-addr.arpa. on 192.168.0.1:53: write udp 192.168.0.108:56942->119.29.29.29:53: i/o timeout
		/*if lookup != nil {
			fmt.Println(lookup)
		}*/

	}
}
