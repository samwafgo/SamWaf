package test

import (
	"fmt"
	dlp "github.com/bytedance/godlp"
	"testing"
)

func TestDesen(t *testing.T) {
	caller := "my"
	if eng, err := dlp.NewEngine(caller); err == nil {
		eng.ApplyConfigDefault()
		fmt.Printf("DLP %s Demo:\n\n", eng.GetVersion())
		inStr := `我的邮件是abcd@abcd.com,
18612341234是我的电话
你家住在哪里啊? 我家住在北京市海淀区北三环西路43号,
mac地址 06-06-06-aa-bb-cc
收件人：张真人  手机号码：13900000000`
		if outStr, _, err := eng.Deidentify(inStr); err == nil {
			fmt.Printf("\t1. Deidentify( inStr: %s )\n", inStr)
			fmt.Printf("\toutStr: %s\n", outStr)
			//eng.ShowResults(results)
			fmt.Println()
		}
		eng.Close()
	} else {
		fmt.Println("[dlp] NewEngine error: ", err.Error())
	}
}
