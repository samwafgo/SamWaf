package wafcli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"SamWaf/model/request"
)

const maxInputBytes = 10 << 20

func editableFields() map[string]bool {
	fields := map[string]bool{}
	t := reflect.TypeOf(request.WafHostEditReq{})
	for i := 0; i < t.NumField(); i++ {
		k := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]
		if k != "" && k != "-" {
			fields[k] = true
		}
	}
	return fields
}

func readSiteInput(path string, stdin io.Reader) ([]siteRecord, error) {
	var r io.Reader = stdin
	if path != "-" {
		f, err := os.Open(filepath.Clean(path))
		if err != nil {
			return nil, fail(ExitUsage, errors.New("无法读取站点配置文件"))
		}
		defer f.Close()
		r = f
	}
	b, err := io.ReadAll(io.LimitReader(r, maxInputBytes+1))
	if err != nil || len(b) > maxInputBytes {
		return nil, fail(ExitUsage, errors.New("读取配置失败或文件超过10MB"))
	}
	b = bytes.TrimSpace(b)
	var items []siteRecord
	if len(b) > 0 && b[0] == '{' {
		var m siteRecord
		err = json.Unmarshal(b, &m)
		items = []siteRecord{m}
	} else {
		err = json.Unmarshal(b, &items)
	}
	if err != nil || len(items) == 0 {
		return nil, fail(ExitUsage, errors.New("配置必须是JSON对象或非空对象数组"))
	}
	fields := editableFields()
	for i, m := range items {
		if len(m) == 0 {
			return nil, fail(ExitUsage, fmt.Errorf("第%d项：站点配置不能为空", i+1))
		}
		for k, v := range m {
			if !fields[k] {
				return nil, fail(ExitUsage, fmt.Errorf("第%d项：未知字段 %s", i+1, k))
			}
			if k == "keyfile" || k == "certfile" {
				return nil, fail(ExitUsage, fmt.Errorf("第%d项：请通过证书管理上传证书并使用 bind_ssl_id", i+1))
			}
			if bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
				return nil, fail(ExitUsage, fmt.Errorf("第%d项：字段 %s 不允许null，请用空字符串或0", i+1, k))
			}
		}
		// 不回显输入值，避免在错误中泄露配置内容。
		data, _ := json.Marshal(m)
		var typed request.WafHostEditReq
		if err = json.Unmarshal(data, &typed); err != nil {
			var e *json.UnmarshalTypeError
			if errors.As(err, &e) {
				return nil, fail(ExitUsage, fmt.Errorf("第%d项：字段 %s 类型错误，应为%s", i+1, e.Field, e.Type))
			}
			return nil, fail(ExitUsage, fmt.Errorf("第%d项：配置类型错误", i+1))
		}
		if recordString(m, "code") == "" && (recordString(m, "host") == "" || recordInt(m, "port") == 0) {
			return nil, fail(ExitUsage, fmt.Errorf("第%d项：需要code或host和port", i+1))
		}
	}
	return items, nil
}

func parseSiteRef(ref string) (code, host string, port int, err error) {
	if strings.TrimSpace(ref) == "" {
		return "", "", 0, fail(ExitUsage, errors.New("站点标识不能为空"))
	}
	i := strings.LastIndex(ref, ":")
	if i > 0 {
		if p, e := strconv.Atoi(ref[i+1:]); e == nil && p >= 1 && p <= 65535 {
			host = strings.Trim(ref[:i], "[]")
			return "", host, p, nil
		}
	}
	return ref, "", 0, nil
}

func filterEditable(cur siteRecord, export bool) siteRecord {
	out := siteRecord{}
	fields := editableFields()
	for k, v := range cur {
		if fields[k] {
			if export && (k == "keyfile" || k == "certfile" || k == "custom_headers_json" || k == "custom_response_headers_json") {
				continue
			}
			out[k] = append(json.RawMessage(nil), v...)
		}
	}
	return out
}

func mergeSite(cur, in siteRecord) (siteRecord, []string, error) {
	body := filterEditable(cur, false)
	changed := []string{}
	if cur == nil {
		_ = json.Unmarshal([]byte(createDefaultsJSON), &body)
	}
	for k, v := range in {
		var a, b any
		_ = json.Unmarshal(body[k], &a)
		_ = json.Unmarshal(v, &b)
		if !reflect.DeepEqual(a, b) {
			changed = append(changed, k)
		}
		body[k] = v
	}
	if cur != nil {
		body["code"] = cur["code"]
		if _, ok := in["port_listens_json"]; !ok {
			delete(body, "port_listens_json")
		}
	}
	sort.Strings(changed)
	if err := validateSite(body); err != nil {
		return nil, nil, err
	}
	return body, changed, nil
}

func validateSite(body siteRecord) error {
	data, _ := json.Marshal(body)
	var v request.WafHostEditReq
	if json.Unmarshal(data, &v) != nil {
		return fail(ExitUsage, errors.New("站点配置字段类型错误"))
	}
	if strings.TrimSpace(v.Host) == "" || len(v.Host) > 255 || strings.ContainsAny(v.Host, "\r\n\x00") {
		return fail(ExitUsage, errors.New("host必须是1至255字节的域名或IP"))
	}
	if v.Port < 1 || v.Port > 65535 || v.Remote_port < 1 || v.Remote_port > 65535 {
		return fail(ExitUsage, errors.New("port和remote_port必须在1至65535之间"))
	}
	u, err := url.Parse(v.Remote_host)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.Port() != "" {
		return fail(ExitUsage, errors.New("remote_host需要http或https域名/IP地址，端口单独写remote_port，不含路径、用户信息或查询参数"))
	}
	if v.Remote_ip != "" && net.ParseIP(v.Remote_ip) == nil {
		return fail(ExitUsage, errors.New("remote_ip必须是IP地址或空字符串"))
	}
	if v.START_STATUS != 0 && v.START_STATUS != 1 {
		return fail(ExitUsage, errors.New("start_status必须为0或1"))
	}
	return nil
}
