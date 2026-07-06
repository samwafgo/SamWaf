package wechatwork

import (
	"SamWaf/utils"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// WechatWorkNotifier 企业微信通知器
type WechatWorkNotifier struct {
	WebhookURL string
}

// NewWechatWorkNotifier 创建企业微信通知器
func NewWechatWorkNotifier(webhookURL string) *WechatWorkNotifier {
	return &WechatWorkNotifier{
		WebhookURL: webhookURL,
	}
}

// WechatWorkMessage 企业微信消息结构
type WechatWorkMessage struct {
	MsgType  string                 `json:"msgtype"`
	Markdown map[string]interface{} `json:"markdown,omitempty"`
	Text     map[string]interface{} `json:"text,omitempty"`
}

// SendMarkdown 发送Markdown消息
func (w *WechatWorkNotifier) SendMarkdown(title, content string) error {
	message := WechatWorkMessage{
		MsgType: "markdown",
		Markdown: map[string]interface{}{
			"content": fmt.Sprintf("# %s\n\n%s", title, content),
		},
	}
	return w.send(message)
}

// SendText 发送文本消息
func (w *WechatWorkNotifier) SendText(content string) error {
	message := WechatWorkMessage{
		MsgType: "text",
		Text: map[string]interface{}{
			"content": content,
		},
	}
	return w.send(message)
}

// send 发送消息
func (w *WechatWorkNotifier) send(message WechatWorkMessage) error {
	// 序列化消息
	payload, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("序列化消息失败: %v", err)
	}

	// 发送HTTP请求
	// N5
	resp, err := utils.SafeHTTPClient().Post(w.WebhookURL, "application/json", bytes.NewBuffer(payload))
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
		return fmt.Errorf("企业微信返回错误: %v", result["errmsg"])
	}

	return nil
}
