package waftunnelengine

import (
	"SamWaf/model"
	"testing"
)

// 纯 IPv6 地址（::1）不得被当成"带端口的完整地址"再拆一次
func TestCheckIPAccessIPv6Loopback(t *testing.T) {
	tun := model.Tunnel{}
	if !CheckIPAccess("TCP", "::1", "45078", "3666", tun) {
		t.Fatal("纯IPv6 ::1 应允许访问")
	}
}

// 兼容历史调用方式：传完整地址 [::1]:45078 仍能正确拆出主机
func TestCheckIPAccessIPv6HostPort(t *testing.T) {
	tun := model.Tunnel{}
	if !CheckIPAccess("TCP", "[::1]:45078", "45078", "3666", tun) {
		t.Fatal("完整IPv6地址 [::1]:45078 应允许访问")
	}
}

// IPv4 纯地址与完整地址两种形态
func TestCheckIPAccessIPv4Forms(t *testing.T) {
	tun := model.Tunnel{}
	if !CheckIPAccess("TCP", "192.168.1.10", "50000", "3666", tun) {
		t.Fatal("纯IPv4地址应允许访问")
	}
	if !CheckIPAccess("TCP", "192.168.1.10:50000", "50000", "3666", tun) {
		t.Fatal("完整IPv4地址应允许访问")
	}
}

// IPv6 命中黑名单/白名单的精确与 CIDR 匹配
func TestCheckIPAccessIPv6ListMatch(t *testing.T) {
	deny := model.Tunnel{DenyIp: "::1"}
	if CheckIPAccess("TCP", "::1", "45078", "3666", deny) {
		t.Fatal("IPv6黑名单精确匹配应拒绝")
	}
	denyCIDR := model.Tunnel{DenyIp: "::1/128"}
	if CheckIPAccess("TCP", "::1", "45078", "3666", denyCIDR) {
		t.Fatal("IPv6黑名单CIDR匹配应拒绝")
	}
	allow := model.Tunnel{AllowIp: "2001:db8::1"}
	if CheckIPAccess("TCP", "::1", "45078", "3666", allow) {
		t.Fatal("不在白名单的IPv6应拒绝")
	}
	if !CheckIPAccess("TCP", "[2001:db8::1]:45078", "45078", "3666", allow) {
		t.Fatal("白名单内的IPv6完整地址应允许")
	}
}

// 空 IP 拒绝；畸形地址拆分失败仍拒绝（不 panic）
func TestCheckIPAccessInvalidInput(t *testing.T) {
	tun := model.Tunnel{}
	if CheckIPAccess("TCP", "", "45078", "3666", tun) {
		t.Fatal("空IP应拒绝")
	}
	if CheckIPAccess("TCP", "1:2:3:4:5:6:7:8:9", "45078", "3666", tun) {
		t.Fatal("无法拆分且非法的地址应拒绝")
	}
}
