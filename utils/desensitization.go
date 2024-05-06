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
