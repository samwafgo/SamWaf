package dingtalk

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// DingTalkNotifier 钉钉通知器
type DingTalkNotifier struct {
	WebhookURL string
	Secret     string
}

// NewDingTalkNotifier 创建钉钉通知器
func NewDingTalkNotifier(webhookURL, secret string) *DingTalkNotifier {
	return &DingTalkNotifier{
		WebhookURL: webhookURL,
		Secret:     secret,
	}
}

// DingTalkMessage 钉钉消息结构
type DingTalkMessage struct {
	MsgType  string                 `json:"msgtype"`
	Markdown map[string]interface{} `json:"markdown,omitempty"`
	Text     map[string]interface{} `json:"text,omitempty"`
}

// SendMarkdown 发送Markdown消息
func (d *DingTalkNotifier) SendMarkdown(title, content string) error {
	message := DingTalkMessage{
		MsgType: "markdown",
		Markdown: map[string]interface{}{
			"title": title,
			"text":  content,
		},
	}
	return d.send(message)
}

// SendText 发送文本消息
func (d *DingTalkNotifier) SendText(content string) error {
	message := DingTalkMessage{
		MsgType: "text",
		Text: map[string]interface{}{
			"content": content,
		},
	}
	return d.send(message)
}

// send 发送消息
func (d *DingTalkNotifier) send(message DingTalkMessage) error {
	// 构建URL（包含签名）
	urlWithSign, err := d.buildURL()
	if err != nil {
		return fmt.Errorf("构建URL失败: %v", err)
	}

	// 序列化消息
	payload, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("序列化消息失败: %v", err)
	}

	// 发送HTTP请求
	resp, err := http.Post(urlWithSign, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("发送HTTP请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应失败: %v", err)
	}

	// 解析响应
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("解析响应失败: %v", err)
	}

	// 检查响应码
	if errCode, ok := result["errcode"].(float64); ok && errCode != 0 {
		return fmt.Errorf("钉钉返回错误: %v", result["errmsg"])
	}

	return nil
}

// buildURL 构建包含签名的URL
func (d *DingTalkNotifier) buildURL() (string, error) {
	if d.Secret == "" {
		return d.WebhookURL, nil
	}

	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
	sign, err := d.sign(timestamp)
	if err != nil {
		return "", err
	}

	u, err := url.Parse(d.WebhookURL)
	if err != nil {
		return "", err
	}

	query := u.Query()
	query.Set("timestamp", timestamp)
	query.Set("sign", sign)
	u.RawQuery = query.Encode()

	return u.String(), nil
}

// sign 计算签名
func (d *DingTalkNotifier) sign(timestamp string) (string, error) {
	stringToSign := timestamp + "\n" + d.Secret
	h := hmac.New(sha256.New, []byte(d.Secret))
	h.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return url.QueryEscape(signature), nil
}
