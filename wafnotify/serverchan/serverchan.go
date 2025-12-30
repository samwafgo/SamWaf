package serverchan

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// ServerChanNotifier Server酱通知器
type ServerChanNotifier struct {
	SendKey string
	ApiURL  string
}

// NewServerChanNotifier 创建Server酱通知器
// sendKey: Server酱的SendKey
func NewServerChanNotifier(sendKey string) (*ServerChanNotifier, error) {
	if sendKey == "" {
		return nil, fmt.Errorf("SendKey不能为空")
	}

	// 根据 sendkey 是否以 "sctp" 开头决定 API 的 URL
	var apiUrl string
	if strings.HasPrefix(sendKey, "sctp") {
		// 使用正则表达式提取数字部分
		re := regexp.MustCompile(`sctp(\d+)t`)
		matches := re.FindStringSubmatch(sendKey)
		if len(matches) > 1 {
			num := matches[1]
			apiUrl = fmt.Sprintf("https://%s.push.ft07.com/send/%s.send", num, sendKey)
		} else {
			return nil, fmt.Errorf("SendKey格式错误: %s", sendKey)
		}
	} else {
		apiUrl = fmt.Sprintf("https://sctapi.ftqq.com/%s.send", sendKey)
	}

	return &ServerChanNotifier{
		SendKey: sendKey,
		ApiURL:  apiUrl,
	}, nil
}

// SendMarkdown 发送Markdown格式消息
func (s *ServerChanNotifier) SendMarkdown(title, content string) error {
	return s.send(title, content)
}

// SendText 发送文本消息
func (s *ServerChanNotifier) SendText(title, content string) error {
	return s.send(title, content)
}

// send 内部发送方法
func (s *ServerChanNotifier) send(title, content string) error {
	if title == "" {
		return fmt.Errorf("消息标题不能为空")
	}

	// 标题最大长度限制为32
	if len(title) > 32 {
		title = title[:32]
	}

	// 内容最大长度限制为32KB
	if len(content) > 32*1024 {
		content = content[:32*1024]
	}

	// 构建POST表单数据
	data := url.Values{}
	data.Set("title", title)
	data.Set("desp", content)

	// 创建HTTP客户端
	client := &http.Client{}
	req, err := http.NewRequest("POST", s.ApiURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("创建请求失败: %v", err)
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应失败: %v", err)
	}

	// 检查HTTP状态码
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Server酱返回错误状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}

	// 这里可以进一步解析响应JSON，检查具体的返回状态
	// Server酱的返回格式类似：{"code":0,"message":"success","data":{"pushid":"xxxx","readkey":"yyyy"}}
	// 如果需要严格验证，可以解析JSON检查code是否为0

	return nil
}

// SendWithOptions 发送带额外选项的消息
// options支持的参数：
// - short: 消息卡片内容，最大长度64
// - noip: 是否隐藏调用IP，"1"表示隐藏
// - channel: 动态指定消息通道，如 "9|66"
// - openid: 消息抄送的openid
func (s *ServerChanNotifier) SendWithOptions(title, content string, options map[string]string) error {
	if title == "" {
		return fmt.Errorf("消息标题不能为空")
	}

	// 标题最大长度限制为32
	if len(title) > 32 {
		title = title[:32]
	}

	// 内容最大长度限制为32KB
	if len(content) > 32*1024 {
		content = content[:32*1024]
	}

	// 构建POST表单数据
	data := url.Values{}
	data.Set("title", title)
	data.Set("desp", content)

	// 添加可选参数
	if short, ok := options["short"]; ok && short != "" {
		if len(short) > 64 {
			short = short[:64]
		}
		data.Set("short", short)
	}

	if noip, ok := options["noip"]; ok && noip != "" {
		data.Set("noip", noip)
	}

	if channel, ok := options["channel"]; ok && channel != "" {
		data.Set("channel", channel)
	}

	if openid, ok := options["openid"]; ok && openid != "" {
		data.Set("openid", openid)
	}

	// 创建HTTP客户端
	client := &http.Client{}
	req, err := http.NewRequest("POST", s.ApiURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("创建请求失败: %v", err)
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应失败: %v", err)
	}

	// 检查HTTP状态码
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Server酱返回错误状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}

	return nil
}
