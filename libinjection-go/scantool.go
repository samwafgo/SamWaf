package libinjection

import (
	"SamWaf/innerbean"
	"strings"
)

func IsScan(log innerbean.WebLog) bool {
	url_keywords := []string{"sqlmap", "Appscan", "nessus", "Nessus", "nessus",
		"acunetix-wvs-test-for-some-inexistent-file", "acunetix_wvs_security_test",
		"acunetix", "acunetix_wvs"}

	for _, keyword := range url_keywords {
		if strings.Contains(log.URL, keyword) {
			return true
		}
	}
	return false
}
