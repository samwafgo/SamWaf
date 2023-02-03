package wechat

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
)

// CorpMessage 微信企业消息通用必需字段
type CorpMessage struct {
	ToUser  string `json:"touser"`
	AgentId string `json:"agentid"`
	MsgType string `json:"msgtype"`
}

// TextCard 文本卡片消息字段
type TextCard struct {
	CorpMessage
	TextCard CardContent `json:"textcard"`
}

type CardContent struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Url         string `json:"url"`
}

// PlainText 纯文本消息字段
type PlainText struct {
	CorpMessage
	Text TextContent `json:"text"`
}

type TextContent struct {
	Content string `json:"content"`
}

type CorpResponse struct {
	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
	MsgId   string `json:"msgid"`

	InvalidUser  string `json:"invaliduser"`
	InvalidParty string `json:"invalidparty"`
	InvalidTag   string `json:"invalidtag"`
}

func BuildTextCardMessage(receiverId, agentId, title, description, u string) (textCard []byte, err error) {
	t := TextCard{
		CorpMessage: CorpMessage{
			ToUser:  receiverId,
			AgentId: agentId,
			MsgType: "textcard",
		},
		TextCard: CardContent{
			Title:       title,
			Description: description,
			Url:         u,
		},
	}

	// serialize struct to json string
	textCard, err = json.Marshal(t)
	if err != nil {
		return nil, err
	}

	return
}

func BuildPlainTextMessage(receiverId, agentId, content string) (plainText []byte, err error) {
	t := PlainText{
		CorpMessage: CorpMessage{
			ToUser:  receiverId,
			AgentId: agentId,
			MsgType: "text",
		},
		Text: TextContent{
			Content: content,
		},
	}

	// serialize struct to json string
	plainText, err = json.Marshal(t)
	if err != nil {
		return nil, err
	}

	return
}

func PushCorpMessage(accessToken string, message []byte) (r CorpResponse, err error) {
	params := url.Values{}
	u, _ := url.Parse("https://qyapi.weixin.qq.com/cgi-bin/message/send")
	params.Set("access_token", accessToken)
	u.RawQuery = params.Encode()
	path := u.String()

	// push template string
	resp, err := http.Post(path, "application/json", bytes.NewBuffer(message))
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	err = json.Unmarshal(body, &r)

	return
}
