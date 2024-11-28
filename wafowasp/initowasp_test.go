package wafowasp

import (
	"fmt"
	"testing"
)

func TestOwasp(t *testing.T) {
	owasp := InitOwasp("..")
	tx := owasp.NewTransaction()

	// 127.0.0.1:55555 -> 127.0.0.1:80
	//tx.ProcessConnection("127.0.0.1", 55555, "127.0.0.1", 80)
	// Request URI was /some-url?with=args
	// 模拟请求头
	tx.AddRequestHeader("Host", "www.demo1.com")
	tx.AddRequestHeader("Cookie", "PHPSESSID=e0b36oh5nsrbm0f97d8p8j9ma2")
	tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
	tx.AddRequestHeader("Accept-Encoding", "gzip, deflate")
	tx.AddRequestHeader("Upgrade-Insecure-Requests", "1")
	tx.AddRequestHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8")
	tx.AddRequestHeader("Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2")
	tx.AddRequestHeader("Priority", "u=0, i")
	tx.AddRequestHeader("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0")
	tx.ProcessURI("/control/sqlinject/manifest_error.php?id=-1%27/*%2a%%2f*/union/*%2f%2f*//*!50144select*//*%2f%2f*/1,version()%23", "GET", "HTTP/1.1")

	tx.ProcessRequestHeaders()
	/*bodybuffer := []string{}
	if _, _, err := tx.WriteRequestBody([]byte(strings.Join(bodybuffer, ""))); err != nil {
		fmt.Println(err)
	}*/
	if _, err := tx.ProcessRequestBody(); err != nil {
		fmt.Println(err)
	}

	interrupted := tx.IsInterrupted()
	if interrupted {
		fmt.Println("interrupted")
	}
	if it := tx.Interruption(); it != nil {
		switch it.Action {
		case "deny":
			fmt.Println(it.Status)
			fmt.Println(it.RuleID)
			fmt.Println(it.Data)
			return
		}
	}
}

func TestWafOwasp(t *testing.T) {

}
