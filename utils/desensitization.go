package utils

import (
	"SamWaf/global"
	"fmt"
)

func DeSenText(inStr string) string {

	if outStr, results, err := global.GWAF_DLP.Deidentify(inStr); err == nil {
		fmt.Printf("\t1. Deidentify( inStr: %s )\n", inStr)
		fmt.Printf("\toutStr: %s\n", outStr)
		global.GWAF_DLP.ShowResults(results)
		//fmt.Println()
		return outStr
	}
	return inStr
}

func DeSenTextByCustomMark(markName, inStr string) string {

	// 使用自定义脱敏规则对数据进行脱敏处理
	maskedData, err := global.GWAF_DLP.Mask(inStr, markName)
	if err != nil {
		//fmt.Println("脱敏处理失败:", err)
		return inStr
	} else {
		return maskedData
	}
}
