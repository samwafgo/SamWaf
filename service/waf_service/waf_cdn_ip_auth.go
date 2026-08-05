package waf_service

import (
	"SamWaf/common/zlog"
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
// extraParam JSON: {"zone_id":"zone-xxx","edition":"cn|intl","region":""}
//
//	edition=cn(默认)   中国站(cloud.tencent.com)，接口域名 teo.tencentcloudapi.com
//	edition=intl       国际站(edgeone.ai / tencentcloud.com)，接口域名 teo.intl.tencentcloudapi.com
//
// 两站账号与密钥各自独立，选错站点会返回 AuthFailure.SecretIdNotFound。
func fetchTencentEdgeOneCIDRs(secretId, secretKey, extraParam string) ([]string, error) {
	var extra struct {
		ZoneId  string `json:"zone_id"`
		Edition string `json:"edition"`
		Region  string `json:"region"`
	}
	_ = json.Unmarshal([]byte(strings.TrimSpace(extraParam)), &extra)

	const (
		service = "teo"
		action  = "DescribeOriginACL"
		version = "2022-09-01"
	)
	host := "teo.tencentcloudapi.com"
	if strings.EqualFold(strings.TrimSpace(extra.Edition), "intl") {
		host = "teo.intl.tencentcloudapi.com"
	}
	if strings.TrimSpace(extra.ZoneId) == "" {
		return nil, fmt.Errorf("EdgeOne 需在扩展参数填写 zone_id(站点ID，形如 zone-xxxx)才能查询回源IP段")
	}
	payloadObj, _ := json.Marshal(map[string]string{"ZoneId": strings.TrimSpace(extra.ZoneId)})
	payload := string(payloadObj)

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

	type originACL struct {
		EntireAddresses struct {
			IPv4 []string `json:"IPv4"`
			IPv6 []string `json:"IPv6"`
		} `json:"EntireAddresses"`
	}
	var resp struct {
		Response struct {
			OriginACLInfo struct {
				CurrentOriginACL originACL `json:"CurrentOriginACL"`
				NextOriginACL    originACL `json:"NextOriginACL"`
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
	cur := resp.Response.OriginACLInfo.CurrentOriginACL
	next := resp.Response.OriginACLInfo.NextOriginACL

	// Current + Next 合并入库：腾讯云在回源段变更前会先在 NextOriginACL 给出新段，
	// 并要求 14 个自然日内完成放行，逾期不保 SLA。提前把新段一起认成可信来源，
	// 变更生效时不会踩点掉线；旧段在下一次拉取(Next 转正、旧段消失)时自然淘汰。
	ips := make([]string, 0, 32)
	seen := make(map[string]struct{}, 32)
	appendUniq := func(list []string) int {
		added := 0
		for _, ip := range list {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			if _, dup := seen[ip]; dup {
				continue
			}
			seen[ip] = struct{}{}
			ips = append(ips, ip)
			added++
		}
		return added
	}
	appendUniq(cur.EntireAddresses.IPv4)
	appendUniq(cur.EntireAddresses.IPv6)
	nextAdded := appendUniq(next.EntireAddresses.IPv4)
	nextAdded += appendUniq(next.EntireAddresses.IPv6)

	if len(ips) == 0 {
		return nil, fmt.Errorf("EdgeOne 返回回源IP段为空：请先在 EdgeOne 控制台 站点 > 安全防护 > 源站防护 中开启该功能，并确认 zone_id 填写正确")
	}
	if nextAdded > 0 {
		zlog.Info("EdgeOne 检测到待生效回源段(NextOriginACL)，已提前合并放行",
			"zone_id", strings.TrimSpace(extra.ZoneId), "new_count", nextAdded, "total", len(ips))
	}
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
