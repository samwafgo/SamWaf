package wafbot

import (
	"testing"
)

func TestCheckCallBackIp(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected CallBackIpResult
	}{
		{
			name: "微信支付回调IP-直接匹配",
			ip:   "175.24.214.208",
			expected: CallBackIpResult{
				IsCallBack:   true,
				CallBackName: "微信支付回调",
			},
		},
		{
			name: "微信支付回调IP-范围匹配",
			ip:   "101.226.103.10",
			expected: CallBackIpResult{
				IsCallBack:   true,
				CallBackName: "微信支付回调",
			},
		},
		{
			name: "支付宝回调IP",
			ip:   "110.75.130.1",
			expected: CallBackIpResult{
				IsCallBack:   true,
				CallBackName: "支付宝回调",
			},
		},
		{
			name: "非回调IP",
			ip:   "8.8.8.8",
			expected: CallBackIpResult{
				IsCallBack:   false,
				CallBackName: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckCallBackIp(tt.ip)
			if result.IsCallBack != tt.expected.IsCallBack || result.CallBackName != tt.expected.CallBackName {
				t.Errorf("CheckCallBackIp() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestWeixinPayBackIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected CallBackIpResult
	}{
		{
			name: "微信支付回调IP-直接匹配",
			ip:   "175.24.214.208",
			expected: CallBackIpResult{
				IsCallBack:   true,
				CallBackName: "微信支付回调",
			},
		},
		{
			name: "微信支付回调IP-范围匹配",
			ip:   "101.226.103.10",
			expected: CallBackIpResult{
				IsCallBack:   true,
				CallBackName: "微信支付回调",
			},
		},
		{
			name: "非微信支付回调IP",
			ip:   "8.8.8.8",
			expected: CallBackIpResult{
				IsCallBack:   false,
				CallBackName: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := WeixinPayBackIP(tt.ip)
			if result.IsCallBack != tt.expected.IsCallBack || result.CallBackName != tt.expected.CallBackName {
				t.Errorf("WeixinPayBackIP() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestAlipayPayBackIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected CallBackIpResult
	}{
		{
			name: "支付宝回调IP",
			ip:   "110.75.130.1",
			expected: CallBackIpResult{
				IsCallBack:   true,
				CallBackName: "支付宝回调",
			},
		},
		{
			name: "支付宝回调IP-IPv6",
			ip:   "2400:B200::1",
			expected: CallBackIpResult{
				IsCallBack:   true,
				CallBackName: "支付宝回调",
			},
		},
		{
			name: "非支付宝回调IP",
			ip:   "8.8.8.8",
			expected: CallBackIpResult{
				IsCallBack:   false,
				CallBackName: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AlipayPayBackIP(tt.ip)
			if result.IsCallBack != tt.expected.IsCallBack || result.CallBackName != tt.expected.CallBackName {
				t.Errorf("AlipayPayBackIP() = %v, want %v", result, tt.expected)
			}
		})
	}
}
