package wechat

import (
	"SamWaf/common/zlog"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`

	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

func GetAppAccessToken(appId, appSecret string) (r TokenResponse, err error) {
	newparms := map[string]string{}
	newparms["grant_type"] = "client_credential"
	newparms["appid"] = appId
	newparms["secret"] = appSecret

	var endPoint = "https://api.weixin.qq.com/cgi-bin/token"
	if newparms != nil {
		endPoint += "?"
		var buffer []string
		for k, v := range newparms {
			buffer = append(buffer, fmt.Sprintf("%s=%s", k, url.QueryEscape(v)))
		}
		endPoint += strings.Join(buffer, "&")
	}

	var netTransport = &http.Transport{
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  true,
		MaxIdleConnsPerHost: 50,
	}
	var netClient = http.Client{
		Timeout:   time.Second * 10,
		Transport: netTransport,
	}
	resp, err := netClient.Get(endPoint)
	if err != nil {
		zlog.Error("错误信息", err)
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
