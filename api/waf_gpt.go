package api

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	"SamWaf/wafsec"
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type WafGPTApi struct {
}

// 新增用于解析流式响应的结构体
type StreamResponse struct {
	ID                string         `json:"id"`
	Choices           []StreamChoice `json:"choices"`
	Created           int64          `json:"created"`
	Model             string         `json:"model"`
	SystemFingerprint string         `json:"system_fingerprint"`
	Object            string         `json:"object"`
	Usage             *TokenUsage    `json:"usage,omitempty"` // 只有最后一条消息包含
}

type StreamChoice struct {
	Index        int         `json:"index"`
	Delta        Delta       `json:"delta"`
	FinishReason *string     `json:"finish_reason"` // 使用指针类型处理 null
	Logprobs     interface{} `json:"logprobs"`
}

type Delta struct {
	Content string  `json:"content"`        // 内容增量
	Role    *string `json:"role,omitempty"` // 使用指针处理 null
}

type TokenUsage struct {
	CompletionTokens int `json:"completion_tokens"`
	PromptTokens     int `json:"prompt_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// SendDeltaMessage 发送信息
func SendDeltaMessage(messageChan chan<- string, content string, role ...string) {
	// 设置默认角色为 assistant
	r := "assistant"
	if len(role) > 0 {
		r = role[0]
	}
	encryptStr, _ := wafsec.AesEncrypt([]byte(content), global.GWAF_COMMUNICATION_KEY)
	// 创建消息结构
	msg := Delta{
		Content: encryptStr,
		Role:    &r,
	}

	// 序列化并发送
	if payload, err := json.Marshal(msg); err == nil {
		messageChan <- string(payload)
	}
}
func (w *WafGPTApi) ChatApi(c *gin.Context) {

	var req request.WafGptSendReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 创建一个取消信号通道，用于触发异常退出
		stopChan := make(chan bool)
		messageChan := make(chan string)

		// 启动一个 goroutine，发送流请求并推送时间
		go func() {
			defer close(stopChan)
			defer close(messageChan)

			// 构造基础消息数组
			messages := []model.GptMessage{
				{
					Content: "你是一位信息安全专家,输出如下格式：\n\n风险等级: 0-100\n风险类型:某种注入，跨站等\n风险说明:对风险的阐释",
					Role:    "user",
				},
			}
			// 将History内容转换为消息并追加
			for _, historyItem := range req.History {
				if len(historyItem) < 2 {
					continue // 跳过无效条目
				}
				if historyItem[1] == "远程服务器未返回信息，请检查配置" {
					continue
				}
				messages = append(messages, model.GptMessage{
					Role:    historyItem[0], // 角色类型（system/user/assistant）
					Content: historyItem[1], // 对话内容
				})
			}
			gptReq := model.GPTRequest{
				Messages:         messages,
				Model:            global.GCONFIG_RECORD_GPT_MODEL,
				FrequencyPenalty: 0,
				MaxTokens:        2048,
				PresencePenalty:  0,
				ResponseFormat:   model.GptResponseFormat{Type: "text"},
				Stop:             nil,
				Stream:           true,
				Temperature:      1,
				TopP:             1,
			}

			// 序列化为JSON字符串
			bodyBytes, _ := json.Marshal(gptReq)
			requestBody := string(bodyBytes)

			// 兼容两种URL格式：https://api.deepseek.com 和 https://api.deepseek.com/v1
			apiURL := global.GCONFIG_RECORD_GPT_URL
			if strings.HasSuffix(apiURL, "/v1") {
				// 如果URL已经以/v1结尾，只添加/chat/completions
				apiURL += "/chat/completions"
			} else {
				// 否则添加/v1/chat/completions
				apiURL += "/v1/chat/completions"
			}

			// 创建请求
			req, err := http.NewRequest("POST", apiURL, strings.NewReader(requestBody))
			if err != nil {
				stopChan <- true
				return
			}

			// 设置请求头
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "text/event-stream")
			req.Header.Set("Authorization", "Bearer "+global.GCONFIG_RECORD_GPT_TOKEN)

			// 创建 HTTP 客户端并发送请求
			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				SendDeltaMessage(messageChan, fmt.Sprintf("访问报错%v", err.Error()), "assistant")
				stopChan <- true
				return
			}
			defer resp.Body.Close()

			// 读取流
			// 创建带缓冲的读取器
			reader := bufio.NewReader(resp.Body)
			var buffer bytes.Buffer
			var residual []byte

			for {
				// 读取数据块
				chunk := make([]byte, 1024)
				n, err := reader.Read(chunk)
				if err != nil && err != io.EOF {
					stopChan <- true
					return
				}

				// 合并残留数据和新数据
				buffer.Write(append(residual, chunk[:n]...))
				residual = nil

				// 分割数据包
				for {
					line, err := buffer.ReadBytes('\n')
					if err == io.EOF {
						// 判断残留数据中是否有错误信息
						lineStr := strings.TrimSpace(string(line))
						if strings.Contains(lineStr, `"error":`) {
							SendDeltaMessage(messageChan, fmt.Sprintf("Error: %s", lineStr), "assistant")
							stopChan <- true
							return
						}
						residual = line
						break
					}

					// 处理单行数据
					lineStr := strings.TrimSpace(string(line))
					if strings.HasPrefix(lineStr, "data: ") {
						content := strings.TrimPrefix(lineStr, "data: ")

						// 处理流结束标记
						if content == "[DONE]" {
							SendDeltaMessage(messageChan, "[DONE]", "assistant")
							stopChan <- true
							return
						}

						// 解析JSON数据
						var response StreamResponse
						if err := json.Unmarshal([]byte(content), &response); err != nil {
							continue // 忽略解析错误
						}

						// 处理消息内容
						for _, choice := range response.Choices {
							// 发送内容增量
							if choice.Delta.Content != "" {
								SendDeltaMessage(messageChan, choice.Delta.Content, "assistant")
							}

							// 处理停止条件
							if choice.FinishReason != nil && *choice.FinishReason == "stop" {
								stopChan <- true
								return
							}
						}
					}
				}

				if err == io.EOF {
					break
				}
			}
		}()

		c.Stream(func(w io.Writer) bool {
			// 判断是否接收到停止信号
			select {
			case <-stopChan:
				return false // 退出流式推送
			case message := <-messageChan:
				c.SSEvent("message", message) // 发送事件到客户端
				return true                   // 继续推送
			}
		})
	}
}
