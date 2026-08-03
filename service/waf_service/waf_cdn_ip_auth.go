package waf_service

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// 认证型 CDN 厂商回源段拉取：腾讯云 EdgeOne(TC3-HMAC-SHA256) 与 阿里云 CDN(RPC HMAC-SHA1)。
// 凭证由上层解密后传入，绝不在此持久化或打印。

// cdnAuthHTTPClient 独立 HTTP 客户端(带超时)，避免影响业务请求
var cdnAuthHTTPClient = &http.Client{Timeout: 30 * time.Second}

// ---------------- 腾讯云 EdgeOne：DescribeOriginACL(TC3-HMAC-SHA256) ----------------

// fetchTencentEdgeOneCIDRs 调用腾讯云 EdgeOne DescribeOriginACL 拉取回源 IP 段(EntireAddresses IPv4/IPv6)。
// extraParam JSON: {"zone_id":"zone-xxx","region":""}
func fetchTencentEdgeOneCIDRs(secretId, secretKey, extraParam string) ([]string, error) {
	var extra struct {
		ZoneId string `json:"zone_id"`
		Region string `json:"region"`
	}
	_ = json.Unmarshal([]byte(strings.TrimSpace(extraParam)), &extra)

	const (
		host    = "teo.tencentcloudapi.com"
		service = "teo"
		action  = "DescribeOriginACL"
		version = "2022-09-01"
	)
	payload := "{}"
	if strings.TrimSpace(extra.ZoneId) != "" {
		payload = fmt.Sprintf(`{"ZoneId":"%s"}`, extra.ZoneId)
	}

	now := time.Now().UTC()
	timestamp := fmt.Sprintf("%d", now.Unix())
	date := now.Format("2006-01-02")

	// 1) 规范请求
	canonicalHeaders := "content-type:application/json; charset=utf-8\n" + "host:" + host + "\n"
	signedHeaders := "content-type;host"
	hashedPayload := sha256Hex(payload)
	canonicalRequest := strings.Join([]string{
		"POST", "/", "", canonicalHeaders, signedHeaders, hashedPayload,
	}, "\n")

	// 2) 待签名字符串
	credentialScope := date + "/" + service + "/tc3_request"
	stringToSign := strings.Join([]string{
		"TC3-HMAC-SHA256", timestamp, credentialScope, sha256Hex(canonicalRequest),
	}, "\n")

	// 3) 计算签名
	secretDate := hmacSHA256([]byte("TC3"+secretKey), date)
	secretService := hmacSHA256(secretDate, service)
	secretSigning := hmacSHA256(secretService, "tc3_request")
	signature := hex.EncodeToString(hmacSHA256(secretSigning, stringToSign))

	// 4) 授权头
	authorization := fmt.Sprintf("TC3-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		secretId, credentialScope, signedHeaders, signature)

	req, err := http.NewRequest("POST", "https://"+host, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Host", host)
	req.Header.Set("X-TC-Action", action)
	req.Header.Set("X-TC-Timestamp", timestamp)
	req.Header.Set("X-TC-Version", version)
	if strings.TrimSpace(extra.Region) != "" {
		req.Header.Set("X-TC-Region", extra.Region)
	}

	body, err := doCDNAuthRequest(req)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Response struct {
			OriginACLInfo struct {
				CurrentOriginACL struct {
					EntireAddresses struct {
						IPv4 []string `json:"IPv4"`
						IPv6 []string `json:"IPv6"`
					} `json:"EntireAddresses"`
				} `json:"CurrentOriginACL"`
			} `json:"OriginACLInfo"`
			Error *struct {
				Code    string `json:"Code"`
				Message string `json:"Message"`
			} `json:"Error"`
		} `json:"Response"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("解析腾讯云响应失败: %v", err)
	}
	if resp.Response.Error != nil {
		return nil, fmt.Errorf("腾讯云API错误 %s: %s", resp.Response.Error.Code, resp.Response.Error.Message)
	}
	ips := append([]string{}, resp.Response.OriginACLInfo.CurrentOriginACL.EntireAddresses.IPv4...)
	ips = append(ips, resp.Response.OriginACLInfo.CurrentOriginACL.EntireAddresses.IPv6...)
	return ips, nil
}

// ---------------- 阿里云 CDN：DescribeL2VipsByDomain(RPC HMAC-SHA1) ----------------

// fetchAliyunCIDRs 调用阿里云 CDN DescribeL2VipsByDomain 拉取某域名的 L2 回源节点 VIP(即回源 IP)。
// extraParam JSON: {"domain":"xxx.com","region":"cn-hangzhou"}
func fetchAliyunCIDRs(accessKeyId, accessKeySecret, extraParam string) ([]string, error) {
	var extra struct {
		Domain string `json:"domain"`
		Region string `json:"region"`
	}
	_ = json.Unmarshal([]byte(strings.TrimSpace(extraParam)), &extra)
	if strings.TrimSpace(extra.Domain) == "" {
		return nil, fmt.Errorf("阿里云需在扩展参数填写 domain(加速域名)才能查询回源VIP")
	}

	params := map[string]string{
		"Format":           "JSON",
		"Version":          "2018-05-10",
		"AccessKeyId":      accessKeyId,
		"SignatureMethod":  "HMAC-SHA1",
		"Timestamp":        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"SignatureVersion": "1.0",
		"SignatureNonce":   fmt.Sprintf("%d", time.Now().UnixNano()),
		"Action":           "DescribeL2VipsByDomain",
		"DomainName":       extra.Domain,
	}

	// 规范化查询串(按 key 排序 + RFC3986 编码)
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var pairs []string
	for _, k := range keys {
		pairs = append(pairs, aliyunPercentEncode(k)+"="+aliyunPercentEncode(params[k]))
	}
	canonicalized := strings.Join(pairs, "&")

	stringToSign := "GET&" + aliyunPercentEncode("/") + "&" + aliyunPercentEncode(canonicalized)
	mac := hmac.New(sha1.New, []byte(accessKeySecret+"&"))
	mac.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	reqURL := "https://cdn.aliyuncs.com/?" + canonicalized + "&Signature=" + aliyunPercentEncode(signature)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	body, err := doCDNAuthRequest(req)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Vips      []string `json:"Vips"`
		Code      string   `json:"Code"`
		Message   string   `json:"Message"`
		RequestId string   `json:"RequestId"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("解析阿里云响应失败: %v", err)
	}
	if resp.Code != "" {
		return nil, fmt.Errorf("阿里云API错误 %s: %s", resp.Code, resp.Message)
	}
	return resp.Vips, nil
}

// ---------------- 公共辅助 ----------------

func doCDNAuthRequest(req *http.Request) ([]byte, error) {
	resp, err := cdnAuthHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20)) // ≤8MB
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncateStatus(string(body)))
	}
	return body, nil
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

// aliyunPercentEncode 阿里云 RFC3986 百分号编码
func aliyunPercentEncode(s string) string {
	e := url.QueryEscape(s)
	e = strings.ReplaceAll(e, "+", "%20")
	e = strings.ReplaceAll(e, "*", "%2A")
	e = strings.ReplaceAll(e, "%7E", "~")
	return e
}
