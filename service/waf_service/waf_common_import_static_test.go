package waf_service

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"SamWaf/model"
)

// 导入按新增处理：开启的静态站点同样受允许目录约束，被拒的行不入库。
func TestImportHostsExcelStaticRoot(t *testing.T) {
	db := setupHostGroupTestDB(t)
	allowed := withStaticAllowed(t)
	typ := reflect.TypeOf(model.Hosts{})
	header := make([]string, 0, typ.NumField())
	fields := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Name == "BaseOrm" {
			continue
		}
		header = append(header, f.Tag.Get("json"))
		fields = append(fields, f.Name)
	}
	hostRow := func(host string, enable int, dir string) []string {
		cfg, _ := json.Marshal(model.StaticSiteConfig{IsEnableStaticSite: enable, StaticSitePath: dir, StaticSitePrefix: "/"})
		row := make([]string, len(header))
		for i := range row {
			row[i] = "0"
		}
		for i, name := range fields {
			switch name {
			case "Host":
				row[i] = host
			case "Port":
				row[i] = "8081"
			case "Remote_host":
				row[i] = "127.0.0.1"
			case "Remote_port":
				row[i] = "80"
			case "StaticSiteJSON":
				row[i] = string(cfg)
			}
		}
		return row
	}
	res := ImportHostsExcel([][]string{header,
		hostRow("ok.test", 1, allowed),
		hostRow("bad.test", 1, ""),
	}, "0")
	if res.SuccessInt != 1 || res.FailInt != 1 {
		t.Fatalf("success=%d fail=%d msg=%s", res.SuccessInt, res.FailInt, res.Msg)
	}
	if !strings.Contains(res.Msg, "StaticSiteJSON") || !strings.Contains(res.Msg, "invalid") {
		t.Fatalf("unexpected message: %s", res.Msg)
	}
	var cnt int64
	db.Model(&model.Hosts{}).Where("host = ?", "bad.test").Count(&cnt)
	if cnt != 0 {
		t.Fatal("rejected row must not be inserted")
	}
	db.Model(&model.Hosts{}).Where("host = ?", "ok.test").Count(&cnt)
	if cnt != 1 {
		t.Fatal("allowed row should be inserted")
	}
}
