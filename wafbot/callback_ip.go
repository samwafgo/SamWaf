package wafbot

import "SamWaf/utils"

// CallBackIpResult 检测结果
type CallBackIpResult struct {
	IsCallBack   bool   //是否是正常回调
	CallBackName string //回调名称
}

func CheckCallBackIp(ip string) CallBackIpResult {
	result := WeixinPayBackIP(ip)
	if result.IsCallBack == true {
		return result
	}
	result = AlipayPayBackIP(ip)
	if result.IsCallBack == true {
		return result
	}
	return CallBackIpResult{IsCallBack: false, CallBackName: ""}
}

func WeixinPayBackIP(ip string) CallBackIpResult {

	ips := []string{
		"175.24.214.208",
		"175.24.211.24",
		"175.24.213.135", "109.244.180.23", "114.132.203.119", "43.139.43.69",
	}
	for _, v := range ips {
		if ip == v {
			return CallBackIpResult{IsCallBack: true, CallBackName: "微信支付回调"}
		}
	}
	ipRanges := []string{
		"101.226.103.0/25",
		"140.207.54.0/25",
		"121.51.58.128/25",
		"183.3.234.0/25",
		"58.251.80.0/25",
		"121.51.30.128/25",
		"203.205.219.128/25",
	}
	isInRanges := utils.CheckIPInRanges(ip, ipRanges)
	if isInRanges == true {
		return CallBackIpResult{IsCallBack: true, CallBackName: "微信支付回调"}
	}
	return CallBackIpResult{IsCallBack: false, CallBackName: ""}
}

func AlipayPayBackIP(ip string) CallBackIpResult {
	ipRanges := []string{
		"103.47.4.0/22",
		"103.52.196.0/22",
		"110.75.128.0/19",
		"110.75.224.0/19",
		"110.76.0.0/19",
		"110.76.48.0/20",
		"119.42.224.0/19",
		"203.209.224.0/19",
		"43.227.188.0/22",
		"45.113.40.0/22",
		"8.150.0.0/17",
		"2400:B200::/32",
	}
	isInRanges := utils.CheckIPInRanges(ip, ipRanges)
	if isInRanges == true {
		return CallBackIpResult{IsCallBack: true, CallBackName: "支付宝回调"}
	}
	return CallBackIpResult{IsCallBack: false, CallBackName: ""}
}
