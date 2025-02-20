package wafenginecore

import (
	"SamWaf/wafenginecore/wafhttpcore"
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// 替换Body字符串内容
func (waf *WafEngine) ReplaceBodyContent(r *http.Request, oldString string, newString string) error {
	var bodyByte []byte
	bodyByte, _ = io.ReadAll(r.Body)
	bodyByte = bytes.ReplaceAll(bodyByte, []byte(oldString), []byte(newString))
	r.Body = io.NopCloser(bytes.NewBuffer(bodyByte))
	return nil
}

// 替换URL字符串内容
func (waf *WafEngine) ReplaceURLContent(r *http.Request, oldString string, newString string) error {
	// 深拷贝原始URL
	originalURL := r.URL
	newURL, _ := url.Parse(originalURL.String())

	// 处理路径部分
	decodedPath, err := url.PathUnescape(newURL.Path)
	if err == nil {
		modifiedPath := strings.ReplaceAll(decodedPath, oldString, newString)
		if decodedPath != modifiedPath {
			newURL.Path = modifiedPath
		} else {
			newURL.Path = originalURL.Path
		}

	}

	rawQuery := newURL.RawQuery
	if rawQuery != "" {
		var queryParts []string
		// 拆分保留原始顺序
		pairs := strings.Split(rawQuery, "&")

		for _, pair := range pairs {
			// 分割键值对（考虑空值和包含多个=的情况）
			key, value, _ := strings.Cut(pair, "=")
			originalKey := key

			// 处理参数值
			if value != "" {
				// 保存原始编码值
				originalEncoded := value
				// 递归解码
				decodedValue := wafhttpcore.WafHttpCoreUrlEncode(value, 5)
				// 执行替换
				modifiedValue := strings.ReplaceAll(decodedValue, oldString, newString)

				// 判断是否需要重新编码
				if modifiedValue != decodedValue {
					value = url.QueryEscape(modifiedValue)
				} else {
					value = originalEncoded // 保留原始编码
				}
			}
			// 重新构建键值对
			if value == "" {
				queryParts = append(queryParts, key)
			} else {
				queryParts = append(queryParts, originalKey+"="+value)
			}
		}

		// 重新组合查询字符串
		newURL.RawQuery = strings.Join(queryParts, "&")
	} else {
		newURL.RawQuery = ""
	}

	*r.URL = *newURL

	r.RequestURI = newURL.RequestURI()
	return nil
}

// 替换Form字符串内容
func (waf *WafEngine) ReplaceFormContent(r *http.Request, oldString string, newString string) error {

	return nil
}
