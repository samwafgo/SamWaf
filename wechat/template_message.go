package wechat

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
)

type TemplateMessage struct {
	ToUser     string  `json:"touser"`
	TemplateId string  `json:"template_id"`
	Data       Content `json:"data"`
}

type Content struct {
	From        Item `json:"from"`
	Description Item `json:"description"`
	Remark      Item `json:"remark"`
}

type Item struct {
	Value string `json:"value"`
	Color string `json:"color"`
}

type TemplateResponse struct {
	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
	MsgId   int    `json:"msgid"`
}

func BuildTemplateMessage(receiverId, templateId, from, description, remark string) (templateMessage []byte, err error) {
	t := TemplateMessage{
		ToUser:     receiverId,
		TemplateId: templateId,
		Data: Content{
			From: Item{
				Value: from,
				Color: "#808080",
			},
			Description: Item{
				Value: description,
				Color: "#000000",
			},
			Remark: Item{
				Value: remark,
				Color: "#808080",
			},
		},
	}

	// serialize struct to json string
	templateMessage, err = json.Marshal(t)
	if err != nil {
		return nil, err
	}

	return
}

func PushTemplateMessage(accessToken string, template []byte) (r TemplateResponse, err error) {
	params := url.Values{}
	u, _ := url.Parse("https://api.weixin.qq.com/cgi-bin/message/template/send")
	params.Set("access_token", accessToken)
	u.RawQuery = params.Encode()
	path := u.String()

	// push template string
	resp, err := http.Post(path, "application/json", bytes.NewBuffer(template))
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	err = json.Unmarshal(body, &r)

	return
}
