package wechat

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
)

type TemplateMessage struct {
	ToUser      string               `json:"touser"`          // 必须, 接受者OpenID
	TemplateID  string               `json:"template_id"`     // 必须, 模版ID
	URL         string               `json:"url,omitempty"`   // 可选, 用户点击后跳转的URL, 该URL必须处于开发者在公众平台网站中设置的域中
	Color       string               `json:"color,omitempty"` // 可选, 整个消息的颜色, 可以不设置
	Data        map[string]*DataItem `json:"data"`            // 必须, 模板数据
	MiniProgram struct {
		AppID    string `json:"appid"`    //所需跳转到的小程序appid（该小程序appid必须与发模板消息的公众号是绑定关联关系）
		PagePath string `json:"pagepath"` //所需跳转到小程序的具体页面路径，支持带参数,（示例index?foo=bar）
	} `json:"miniprogram"` //可选,跳转至小程序地址
}

// DataItem 模版内某个 .DATA 的值
type DataItem struct {
	Value string `json:"value"`
	Color string `json:"color,omitempty"`
}

type TemplateResponse struct {
	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
	MsgId   int    `json:"msgid"`
}

func BuildTemplateMessage(receiverId, templateId string, dataItems map[string]*DataItem) (templateMessage []byte, err error) {
	t := TemplateMessage{
		ToUser:     receiverId,
		TemplateID: templateId,
		Data:       dataItems,
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
