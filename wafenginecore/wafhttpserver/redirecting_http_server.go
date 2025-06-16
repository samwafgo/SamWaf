package wafhttpserver

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

type RedirectingHTTPSServer struct {
	*http.Server
	ExtConfig string
}

func (s *RedirectingHTTPSServer) ListenAndServeTLS(certFile, keyFile string) error {
	addr := s.Addr
	if addr == "" {
		addr = ":https"
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	return s.ServeTLS(&redirectingListener{
		Listener:  listener,
		extConfig: s.ExtConfig,
	}, certFile, keyFile)
}

type redirectingListener struct {
	net.Listener
	extConfig string
}

func (l *redirectingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return &redirectingConn{
		Conn:      conn,
		extConfig: l.extConfig,
	}, nil
}

type redirectingConn struct {
	net.Conn
	extConfig string
	firstRead bool
}

func (c *redirectingConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)

	// 只在第一次读取时检查
	if !c.firstRead && n > 0 {
		c.firstRead = true

		// 检查是否为HTTP请求
		data := string(b[:n])
		if strings.HasPrefix(data, "GET ") ||
			strings.HasPrefix(data, "POST ") ||
			strings.HasPrefix(data, "PUT ") ||
			strings.HasPrefix(data, "HEAD ") ||
			strings.HasPrefix(data, "OPTIONS ") ||
			strings.HasPrefix(data, "DELETE ") {

			// 解析HTTP请求行和Host头
			lines := strings.Split(data, "\r\n")
			if len(lines) > 0 {
				// 解析请求行 (例如: "GET /path?query HTTP/1.1")
				requestLine := lines[0]
				parts := strings.Split(requestLine, " ")

				var requestPath string
				var queryString string
				if len(parts) >= 2 {
					urlPart := parts[1]
					if strings.Contains(urlPart, "?") {
						urlParts := strings.SplitN(urlPart, "?", 2)
						requestPath = urlParts[0]
						queryString = urlParts[1]
					} else {
						requestPath = urlPart
					}
				}

				// 查找Host头
				var host string
				for _, line := range lines[1:] {
					if strings.HasPrefix(strings.ToLower(line), "host:") {
						host = strings.TrimSpace(line[5:])
						break
					}
				}

				// 构建HTTPS重定向URL
				var targetHttpsUrl string
				if host != "" {
					// 检查host是否包含端口
					if strings.Contains(host, ":") {
						// 如果host包含端口，需要处理HTTPS端口
						hostParts := strings.Split(host, ":")
						hostName := hostParts[0]
						port := hostParts[1]

						// 如果是标准端口（80或443），不显示端口号
						if port == "80" || port == "443" {
							targetHttpsUrl = fmt.Sprintf("https://%s%s", hostName, requestPath)
						} else {
							// 非标准端口，显示端口号
							targetHttpsUrl = fmt.Sprintf("https://%s:%s%s", hostName, port, requestPath)
						}
					} else {
						// host不包含端口，使用默认HTTPS端口443（不显示端口号）
						targetHttpsUrl = fmt.Sprintf("https://%s%s", host, requestPath)
					}

					// 添加查询参数
					if queryString != "" {
						targetHttpsUrl += "?" + queryString
					}
				} else {
					return 0, fmt.Errorf("redirected to HTTPS not find host")
				}

				// 发送重定向响应
				redirectResponse := fmt.Sprintf(
					"HTTP/1.1 301 Moved Permanently\r\n"+
						"Location: %s\r\n"+
						"Connection: close\r\n"+
						"\r\n",
					targetHttpsUrl,
				)

				c.Conn.Write([]byte(redirectResponse))
				c.Conn.Close()
				return 0, fmt.Errorf("redirected to HTTPS")
			}
		}
	}

	return n, err
}
