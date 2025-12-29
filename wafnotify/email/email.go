package email

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/smtp"
	"strings"
)

// EmailNotifier 邮件通知器
type EmailNotifier struct {
	SMTPHost       string
	SMTPPort       string
	Username       string
	Password       string
	FromEmail      string
	FromName       string
	ToEmails       []string
	EnableSSL      bool
	EnableSTARTTLS bool
}

// EmailConfig 邮件配置
type EmailConfig struct {
	SMTPHost       string   `json:"smtp_host"`
	SMTPPort       string   `json:"smtp_port"`
	Username       string   `json:"username"`
	Password       string   `json:"password"`
	FromEmail      string   `json:"from_email"`
	FromName       string   `json:"from_name"`
	ToEmails       []string `json:"to_emails"`
	EnableSSL      bool     `json:"enable_ssl"`
	EnableSTARTTLS bool     `json:"enable_starttls"`
}

// NewEmailNotifier 创建邮件通知器
// configJSON: JSON格式的配置字符串
func NewEmailNotifier(configJSON string) (*EmailNotifier, error) {
	var config EmailConfig
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return nil, fmt.Errorf("解析邮件配置失败: %v", err)
	}

	// 验证必填字段
	if config.SMTPHost == "" {
		return nil, fmt.Errorf("SMTP服务器地址不能为空")
	}
	if config.SMTPPort == "" {
		return nil, fmt.Errorf("SMTP端口不能为空")
	}
	if config.FromEmail == "" {
		return nil, fmt.Errorf("发件人邮箱不能为空")
	}
	if len(config.ToEmails) == 0 {
		return nil, fmt.Errorf("收件人邮箱不能为空")
	}

	// 提供端口和加密方式的建议（警告但不阻止）
	port := config.SMTPPort
	if config.EnableSSL && (port == "25" || port == "587") {
		// 不返回错误，只是在日志中会显示警告
		fmt.Printf("警告: 端口 %s 通常不支持直接SSL/TLS连接，建议使用端口465或选择STARTTLS加密方式\n", port)
	}
	if config.EnableSTARTTLS && port == "465" {
		fmt.Printf("警告: 端口 465 通常需要直接SSL/TLS连接，建议选择SSL/TLS加密方式或使用端口587\n")
	}

	return &EmailNotifier{
		SMTPHost:       config.SMTPHost,
		SMTPPort:       config.SMTPPort,
		Username:       config.Username,
		Password:       config.Password,
		FromEmail:      config.FromEmail,
		FromName:       config.FromName,
		ToEmails:       config.ToEmails,
		EnableSSL:      config.EnableSSL,
		EnableSTARTTLS: config.EnableSTARTTLS,
	}, nil
}

// SendMarkdown 发送Markdown格式消息（转换为HTML）
func (e *EmailNotifier) SendMarkdown(title, content string) error {
	// 将Markdown格式转换为简单的HTML
	htmlContent := e.markdownToHTML(content)
	return e.SendHTML(title, htmlContent)
}

// SendText 发送纯文本消息
func (e *EmailNotifier) SendText(title, content string) error {
	return e.send(title, content, "text/plain")
}

// SendHTML 发送HTML格式消息
func (e *EmailNotifier) SendHTML(title, content string) error {
	return e.send(title, content, "text/html")
}

// send 发送邮件
func (e *EmailNotifier) send(subject, body, contentType string) error {
	// 构建邮件头
	from := e.FromEmail
	if e.FromName != "" {
		from = fmt.Sprintf("%s <%s>", e.FromName, e.FromEmail)
	}

	headers := make(map[string]string)
	headers["From"] = from
	headers["To"] = strings.Join(e.ToEmails, ",")
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = fmt.Sprintf("%s; charset=UTF-8", contentType)

	// 组装邮件内容
	message := ""
	for k, v := range headers {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + body

	// 获取SMTP服务器地址
	addr := e.SMTPHost + ":" + e.SMTPPort

	// 判断认证方式
	var auth smtp.Auth
	if e.Username != "" && e.Password != "" {
		auth = smtp.PlainAuth("", e.Username, e.Password, e.SMTPHost)
	}

	// 发送邮件
	if e.EnableSSL {
		// 使用SSL/TLS连接
		return e.sendWithTLS(addr, auth, message)
	} else if e.EnableSTARTTLS {
		// 使用STARTTLS
		return e.sendWithSTARTTLS(addr, auth, message)
	} else {
		// 不使用加密
		return e.sendWithPlain(addr, auth, message)
	}
}

// sendWithPlain 不使用加密发送
func (e *EmailNotifier) sendWithPlain(addr string, auth smtp.Auth, message string) error {
	// 建立TCP连接
	client, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("连接SMTP服务器失败: %v", err)
	}
	// 注意：不要使用 defer client.Close()，因为 Quit() 会处理连接关闭

	// 认证
	if auth != nil {
		if err = client.Auth(auth); err != nil {
			client.Close()
			// 如果是未加密连接的认证错误，给出友好提示
			if strings.Contains(err.Error(), "unencrypted connection") {
				return fmt.Errorf("SMTP认证失败: 服务器不允许在未加密连接上进行认证。\n解决方案：\n1. 推荐使用端口587并选择'STARTTLS'加密\n2. 或使用端口465并选择'SSL/TLS'加密\n3. 如果确实要用端口25，请选择'STARTTLS'加密方式\n原始错误: %v", err)
			}
			return fmt.Errorf("SMTP认证失败: %v", err)
		}
	}

	// 设置发件人
	if err = client.Mail(e.FromEmail); err != nil {
		client.Close()
		return fmt.Errorf("设置发件人失败: %v", err)
	}

	// 设置收件人
	for _, to := range e.ToEmails {
		if err = client.Rcpt(to); err != nil {
			client.Close()
			return fmt.Errorf("设置收件人失败: %v", err)
		}
	}

	// 发送邮件内容
	w, err := client.Data()
	if err != nil {
		client.Close()
		return fmt.Errorf("发送邮件数据失败: %v", err)
	}

	_, err = w.Write([]byte(message))
	if err != nil {
		w.Close()
		client.Close()
		return fmt.Errorf("写入邮件内容失败: %v", err)
	}

	// 关闭数据写入
	err = w.Close()
	if err != nil {
		client.Close()
		return fmt.Errorf("关闭邮件数据失败: %v", err)
	}

	// 正确退出SMTP会话（Quit内部会关闭连接）
	err = client.Quit()
	if err != nil {
		// 邮件已经发送成功，Quit错误可以忽略（某些服务器实现不标准）
		if !strings.Contains(err.Error(), "short response") {
			return fmt.Errorf("退出SMTP会话失败: %v", err)
		}
		// short response错误忽略，邮件已发送成功
	}

	return nil
}

// sendWithTLS 使用TLS加密发送
func (e *EmailNotifier) sendWithTLS(addr string, auth smtp.Auth, message string) error {
	// 创建TLS配置
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         e.SMTPHost,
	}

	// 建立TLS连接
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		// 如果是 TLS 握手错误，给出更友好的提示
		if strings.Contains(err.Error(), "first record does not look like a TLS handshake") {
			return fmt.Errorf("TLS连接失败: 端口 %s 不支持直接SSL/TLS连接，请检查：\n1. 如果使用端口25或587，请选择'STARTTLS'或'不加密'\n2. 如果使用端口465，请确认服务器支持SSL/TLS\n原始错误: %v", e.SMTPPort, err)
		}
		return fmt.Errorf("TLS连接失败: %v", err)
	}
	defer conn.Close()

	// 创建SMTP客户端
	client, err := smtp.NewClient(conn, e.SMTPHost)
	if err != nil {
		return fmt.Errorf("创建SMTP客户端失败: %v", err)
	}
	// 注意：不要使用 defer client.Close()，因为 Quit() 会处理连接关闭

	// 认证
	if auth != nil {
		if err = client.Auth(auth); err != nil {
			client.Close() // 认证失败时手动关闭
			return fmt.Errorf("SMTP认证失败: %v", err)
		}
	}

	// 设置发件人
	if err = client.Mail(e.FromEmail); err != nil {
		client.Close() // 失败时手动关闭
		return fmt.Errorf("设置发件人失败: %v", err)
	}

	// 设置收件人
	for _, to := range e.ToEmails {
		if err = client.Rcpt(to); err != nil {
			client.Close() // 失败时手动关闭
			return fmt.Errorf("设置收件人失败: %v", err)
		}
	}

	// 发送邮件内容
	w, err := client.Data()
	if err != nil {
		client.Close() // 失败时手动关闭
		return fmt.Errorf("发送邮件数据失败: %v", err)
	}

	_, err = w.Write([]byte(message))
	if err != nil {
		w.Close()
		client.Close() // 失败时手动关闭
		return fmt.Errorf("写入邮件内容失败: %v", err)
	}

	// 关闭数据写入
	err = w.Close()
	if err != nil {
		client.Close() // 失败时手动关闭
		return fmt.Errorf("关闭邮件数据失败: %v", err)
	}

	// 正确退出SMTP会话（Quit内部会关闭连接）
	err = client.Quit()
	if err != nil {
		// 邮件已经发送成功，Quit错误可以忽略（某些服务器实现不标准）
		// 但如果是关键错误还是要返回
		if !strings.Contains(err.Error(), "short response") {
			return fmt.Errorf("退出SMTP会话失败: %v", err)
		}
		// short response错误忽略，邮件已发送成功
	}

	return nil
}

// sendWithSTARTTLS 使用STARTTLS发送
func (e *EmailNotifier) sendWithSTARTTLS(addr string, auth smtp.Auth, message string) error {
	// 建立TCP连接
	client, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("连接SMTP服务器失败: %v", err)
	}
	// 注意：不要使用 defer client.Close()，因为 Quit() 会处理连接关闭

	// 创建TLS配置
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         e.SMTPHost,
	}

	// 开启STARTTLS
	if err = client.StartTLS(tlsConfig); err != nil {
		client.Close()
		return fmt.Errorf("启动STARTTLS失败: %v", err)
	}

	// 认证
	if auth != nil {
		if err = client.Auth(auth); err != nil {
			client.Close()
			return fmt.Errorf("SMTP认证失败: %v", err)
		}
	}

	// 设置发件人
	if err = client.Mail(e.FromEmail); err != nil {
		client.Close()
		return fmt.Errorf("设置发件人失败: %v", err)
	}

	// 设置收件人
	for _, to := range e.ToEmails {
		if err = client.Rcpt(to); err != nil {
			client.Close()
			return fmt.Errorf("设置收件人失败: %v", err)
		}
	}

	// 发送邮件内容
	w, err := client.Data()
	if err != nil {
		client.Close()
		return fmt.Errorf("发送邮件数据失败: %v", err)
	}

	_, err = w.Write([]byte(message))
	if err != nil {
		w.Close()
		client.Close()
		return fmt.Errorf("写入邮件内容失败: %v", err)
	}

	// 关闭数据写入
	err = w.Close()
	if err != nil {
		client.Close()
		return fmt.Errorf("关闭邮件数据失败: %v", err)
	}

	// 正确退出SMTP会话（Quit内部会关闭连接）
	err = client.Quit()
	if err != nil {
		// 邮件已经发送成功，Quit错误可以忽略（某些服务器实现不标准）
		if !strings.Contains(err.Error(), "short response") {
			return fmt.Errorf("退出SMTP会话失败: %v", err)
		}
		// short response错误忽略，邮件已发送成功
	}

	return nil
}

// markdownToHTML 将简单的Markdown转换为HTML
func (e *EmailNotifier) markdownToHTML(markdown string) string {
	html := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        .info { background-color: #f8f9fa; padding: 15px; border-left: 4px solid #3498db; margin: 10px 0; }
        .label { font-weight: bold; color: #2c3e50; }
        .value { color: #34495e; }
    </style>
</head>
<body>
    <div class="container">
`

	// 简单的Markdown解析
	lines := strings.Split(markdown, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 处理加粗文本 **text**
		if strings.Contains(line, "**") {
			parts := strings.Split(line, "**")
			if len(parts) >= 3 {
				label := parts[1]
				value := ""
				if len(parts) > 2 {
					value = strings.TrimSpace(parts[2])
				}
				html += fmt.Sprintf(`        <div class="info"><span class="label">%s</span> <span class="value">%s</span></div>`, label, value)
				html += "\n"
				continue
			}
		}

		// 普通文本
		html += fmt.Sprintf("        <p>%s</p>\n", line)
	}

	html += `    </div>
</body>
</html>`

	return html
}
