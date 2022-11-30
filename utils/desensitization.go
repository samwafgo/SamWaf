package utils

import (
	"SamWaf/global"
)

func DeSenText(inStr string) string {
	if outStr, _, err := global.GWAF_DLP.Deidentify(inStr); err == nil {
		///fmt.Printf("\t1. Deidentify( inStr: %s )\n", inStr)
		//fmt.Printf("\toutStr: %s\n", outStr)
		//eng.ShowResults(results)
		//fmt.Println()
		return outStr
	}
	return inStr
}
