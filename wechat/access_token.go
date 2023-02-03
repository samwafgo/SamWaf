package wechat

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
)

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`

	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

func GetAppAccessToken(appId, appSecret string) (r TokenResponse, err error) {
	params := url.Values{}
	u, _ := url.Parse("https://api.weixin.qq.com/cgi-bin/token")
	params.Set("grant_type", "client_credential")
	params.Set("appid", appId)
	params.Set("secret", appSecret)
	u.RawQuery = params.Encode()
	path := u.String()

	resp, err := http.Get(path)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	err = json.Unmarshal(body, &r)
	if err != nil {
		return
	}
	return
}

func GetCropAccessToken(corpId, agentSecret string) (r TokenResponse, err error) {
	params := url.Values{}
	u, _ := url.Parse("https://qyapi.weixin.qq.com/cgi-bin/gettoken")
	params.Set("corpid", corpId)
	params.Set("corpsecret", agentSecret)
	u.RawQuery = params.Encode()
	path := u.String()

	resp, err := http.Get(path)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	err = json.Unmarshal(body, &r)
	if err != nil {
		return
	}

	return
}
