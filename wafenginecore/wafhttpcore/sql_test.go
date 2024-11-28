package wafhttpcore

import (
	"SamWaf/libinjection-go"
	"fmt"
	"testing"
)

func TestSql(t *testing.T) {
	payload := "data/index.html?id=1 and (select top 1 count(*) from admin where unicode(substring(a,1,1))=asc%E5%80%BC%20and%20id=1)%3E0"

	sqlB, sqlstring := libinjection.IsSQLi(payload)
	fmt.Println(sqlB, sqlstring)
}
