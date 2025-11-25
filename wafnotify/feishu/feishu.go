package feishu

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// FeishuNotifier 飞书通知器
type FeishuNotifier struct {
	WebhookURL string
	Secret     string
}

// NewFeishuNotifier 创建飞书通知器
func NewFeishuNotifier(webhookURL, secret string) *FeishuNotifier {
	return &FeishuNotifier{
		WebhookURL: webhookURL,
		Secret:     secret,
	}
}

// FeishuMessage 飞书消息结构
type FeishuMessage struct {
	Timestamp string                 `json:"timestamp,omitempty"`
	Sign      string                 `json:"sign,omitempty"`
	MsgType   string                 `json:"msg_type"`
	Content   map[string]interface{} `json:"content,omitempty"`
	Card      map[string]interface{} `json:"card,omitempty"`
}

// SendText 发送文本消息
func (f *FeishuNotifier) SendText(content string) error {
	message := FeishuMessage{
		MsgType: "text",
		Content: map[string]interface{}{
			"text": content,
		},
	}
	return f.send(message)
}

// SendRichText 发送富文本消息
func (f *FeishuNotifier) SendRichText(title, content string) error {
	message := FeishuMessage{
		MsgType: "post",
		Content: map[string]interface{}{
			"post": map[string]interface{}{
				"zh_cn": map[string]interface{}{
					"title": title,
					"content": [][]map[string]interface{}{
						{
							{
								"tag":  "text",
								"text": content,
							},
						},
					},
				},
			},
		},
	}
	return f.send(message)
}

// SendMarkdown 发送Markdown消息（交互式卡片）
func (f *FeishuNotifier) SendMarkdown(title, content string) error {
	message := FeishuMessage{
		MsgType: "interactive",
		Card: map[string]interface{}{
			"config": map[string]interface{}{
				"wide_screen_mode": true,
			},
			"header": map[string]interface{}{
				"title": map[string]interface{}{
					"tag":     "plain_text",
					"content": title,
				},
				"template": "blue",
			},
			"elements": []map[string]interface{}{
				{
					"tag":     "markdown",
					"content": content,
				},
			},
		},
	}
	return f.send(message)
}

// send 发送消息
func (f *FeishuNotifier) send(message FeishuMessage) error {
	// 如果有密钥，添加签名
	if f.Secret != "" {
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		sign, err := f.sign(timestamp)
		if err != nil {
			return fmt.Errorf("生成签名失败: %v", err)
		}
		message.Timestamp = timestamp
		message.Sign = sign
	}

	// 序列化消息
	payload, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("序列化消息失败: %v", err)
	}

	// 发送HTTP请求
	resp, err := http.Post(f.WebhookURL, "application/json", bytes.NewBuffer(payload))
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
	if code, ok := result["code"].(float64); ok && code != 0 {
		return fmt.Errorf("飞书返回错误: %v", result["msg"])
	}

	return nil
}

// sign 计算签名
func (f *FeishuNotifier) sign(timestamp string) (string, error) {
	stringToSign := timestamp + "\n" + f.Secret
	h := hmac.New(sha256.New, []byte(stringToSign))
	h.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return signature, nil
}
