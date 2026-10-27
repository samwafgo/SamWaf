package api

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/service/waf_service"
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/xuri/excelize/v2"
)

// 每次从当前 Hosts 生成样本；新增类型必须明确提供非零测试值。
func excelHostFixture(t *testing.T) model.Hosts {
	t.Helper()
	host := model.Hosts{}
	v := reflect.ValueOf(&host).Elem()
	for i := 0; i < v.NumField(); i++ {
		field := v.Type().Field(i)
		if field.Name == "BaseOrm" {
			continue
		}
		if tag := field.Tag.Get("json"); tag == "" || tag == "-" || strings.Contains(tag, ",") {
			t.Fatalf("Hosts.%s needs an explicit Excel field contract: %q", field.Name, tag)
		}
		switch value := v.Field(i); value.Kind() {
		case reflect.String:
			value.SetString("测试-" + field.Name)
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32:
			value.SetInt(1)
		case reflect.Int64:
			value.SetInt(9223372036854775807)
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			value.SetUint(1)
		case reflect.Bool:
			value.SetBool(true)
		case reflect.Float32, reflect.Float64:
			value.SetFloat(1.25)
		default:
			t.Fatalf("add Excel round-trip coverage for Hosts.%s (%s)", field.Name, field.Type)
		}
	}
	host.BaseOrm = baseorm.BaseOrm{Id: "export-source", USER_CODE: global.GWAF_USER_CODE, Tenant_ID: global.GWAF_TENANT_ID}
	host.Host, host.Port, host.Code = "import.example", 9112, "export-source-code"
	host.GLOBAL_HOST = 0
	return host
}

func excelHostRows(host model.Hosts) [][]string {
	v := reflect.ValueOf(host)
	header, row := make([]string, v.NumField()), make([]string, v.NumField())
	for i := range header {
		if v.Type().Field(i).Name == "BaseOrm" {
			header[i] = " - "
			continue
		}
		header[i] = v.Type().Field(i).Tag.Get("json")
		row[i] = fmt.Sprint(v.Field(i).Interface())
	}
	return [][]string{header, row}
}

func setExcelHostCell(t *testing.T, rows [][]string, field, value string) {
	t.Helper()
	for i, header := range rows[0] {
		if header == field {
			rows[1][i] = value
			return
		}
	}
	t.Fatalf("missing fixture column %s", field)
}

func assertExcelImportedHost(t *testing.T, want model.Hosts, strategy string) {
	t.Helper()
	var hosts []model.Hosts
	if err := global.GWAF_LOCAL_DB.Find(&hosts).Error; err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 {
		t.Fatalf("want exactly one imported host, got %d", len(hosts))
	}
	got := hosts[0]
	if got.Id == "" || got.Id == want.Id || got.USER_CODE != global.GWAF_USER_CODE || got.Tenant_ID != global.GWAF_TENANT_ID || time.Time(got.CREATE_TIME).IsZero() || time.Time(got.UPDATE_TIME).IsZero() {
		t.Fatalf("imported BaseOrm metadata was not generated: %+v", got.BaseOrm)
	}
	gv, wv := reflect.ValueOf(got), reflect.ValueOf(want)
	for i := 0; i < wv.NumField(); i++ {
		name := wv.Type().Field(i).Name
		if name == "BaseOrm" {
			continue
		}
		if name == "Code" && strategy == "0" {
			if got.Code == "" || got.Code == want.Code {
				t.Fatal("strategy 0 must generate a new host code")
			}
			continue
		}
		if !reflect.DeepEqual(gv.Field(i).Interface(), wv.Field(i).Interface()) {
			t.Errorf("Hosts.%s changed during import: want %v, got %v", name, wv.Field(i), gv.Field(i))
		}
	}
}

func exportExcelHost(t *testing.T, host model.Hosts) []byte {
	t.Helper()
	if err := global.GWAF_LOCAL_DB.Create(&host).Error; err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	r.GET("/export", new(WafCommonApi).ExportExcelApi)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/export?table_name=hosts", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("export HTTP %d: %s", rec.Code, rec.Body.String())
	}
	f, err := excelize.OpenReader(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("response is not an Excel workbook: %v", err)
	}
	defer f.Close()
	rows, err := f.GetRows("Sheet1")
	if err != nil {
		t.Fatal(err)
	}
	if want := excelHostRows(host); !reflect.DeepEqual(rows, want) {
		t.Fatalf("exported columns or cell values differ from current Hosts fields\nwant: %v\ngot: %v", want, rows)
	}
	for i, field := range rows[0] {
		if field == "emergency_until" && host.EmergencyUntil > 999999999999999 {
			cell, err := excelize.CoordinatesToCellName(i+1, 2)
			if err != nil {
				t.Fatal(err)
			}
			kind, err := f.GetCellType("Sheet1", cell)
			if err != nil || (kind != excelize.CellTypeSharedString && kind != excelize.CellTypeInlineString) {
				t.Fatalf("large integer must be exported as text: %v %v", kind, err)
			}
		}
	}
	return append([]byte(nil), rec.Body.Bytes()...)
}

func importExcelRequest(t *testing.T, workbook []byte, table, strategy string, includeFile bool) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if includeFile {
		part, err := writer.CreateFormFile("file", "hosts.xlsx")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(workbook); err != nil {
			t.Fatal(err)
		}
	}
	for key, value := range map[string]string{"import_table": table, "import_code_strategy": strategy} {
		if value != "" {
			if err := writer.WriteField(key, value); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	r.POST("/import", func(c *gin.Context) {
		c.Set("is_openapi", true)
		new(WafCommonApi).ImportExcelApi(c)
	})
	req := httptest.NewRequest(http.MethodPost, "/import", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestExportExcelApi(t *testing.T) {
	setupNotifyTestEnv(t, &model.Hosts{})
	t.Chdir(t.TempDir())
	exportExcelHost(t, excelHostFixture(t))
}

func TestHostsExcelRoundTripAllFields(t *testing.T) {
	for _, strategy := range []string{"0", "1"} {
		t.Run("strategy_"+strategy, func(t *testing.T) {
			setupNotifyTestEnv(t, &model.Hosts{})
			t.Chdir(t.TempDir())
			host := excelHostFixture(t)
			workbook := exportExcelHost(t, host)
			if err := global.GWAF_LOCAL_DB.Where("id = ?", host.Id).Delete(&model.Hosts{}).Error; err != nil {
				t.Fatal(err)
			}
			rec := importExcelRequest(t, workbook, "hosts", strategy, true)
			var response struct {
				Code int
				Data waf_service.ReturnImportData
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatalf("decode import result: %v: %s", err, rec.Body.String())
			}
			if rec.Code != http.StatusOK || response.Code != 0 || response.Data.SuccessInt != 1 || response.Data.FailInt != 0 || response.Data.Msg != "" {
				t.Fatalf("round-trip failed: HTTP %d %s", rec.Code, rec.Body.String())
			}
			assertExcelImportedHost(t, host, strategy)
		})
	}
}

func TestHostsExcelImportRawNumericCell(t *testing.T) {
	setupNotifyTestEnv(t, &model.Hosts{})
	t.Chdir(t.TempDir())
	host := excelHostFixture(t)
	workbook := exportExcelHost(t, host)
	f, err := excelize.OpenReader(bytes.NewReader(workbook))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rows, err := f.GetRows("Sheet1")
	if err != nil {
		t.Fatal(err)
	}
	for i, field := range rows[0] {
		if field == "emergency_until" {
			cell, err := excelize.CoordinatesToCellName(i+1, 2)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.SetCellValue("Sheet1", cell, host.EmergencyUntil); err != nil {
				t.Fatal(err)
			}
		}
	}
	buffer, err := f.WriteToBuffer()
	if err != nil {
		t.Fatal(err)
	}
	if err := global.GWAF_LOCAL_DB.Where("id = ?", host.Id).Delete(&model.Hosts{}).Error; err != nil {
		t.Fatal(err)
	}
	rec := importExcelRequest(t, buffer.Bytes(), "hosts", "1", true)
	var response struct {
		Code int
		Data waf_service.ReturnImportData
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || response.Code != 0 || response.Data.SuccessInt != 1 || response.Data.FailInt != 0 || response.Data.Msg != "" {
		t.Fatalf("raw numeric cell import failed: HTTP %d %s", rec.Code, rec.Body.String())
	}
	assertExcelImportedHost(t, host, "1")
}

func TestHostsExcelImportRows(t *testing.T) {
	cases := []struct {
		name    string
		edit    func(*testing.T, [][]string) [][]string
		fail    bool
		message string
	}{
		{"int64_zero", func(t *testing.T, r [][]string) [][]string { setExcelHostCell(t, r, "emergency_until", "0"); return r }, false, ""},
		{"int64_max", func(t *testing.T, r [][]string) [][]string {
			setExcelHostCell(t, r, "emergency_until", "9223372036854775807")
			return r
		}, false, ""},
		{"int64_invalid", func(t *testing.T, r [][]string) [][]string {
			setExcelHostCell(t, r, "emergency_until", "bad")
			return r
		}, true, "EmergencyUntil"},
		{"int64_overflow", func(t *testing.T, r [][]string) [][]string {
			setExcelHostCell(t, r, "emergency_until", "9223372036854775808")
			return r
		}, true, "EmergencyUntil"},
		{"two_invalid_cells_one_failure", func(t *testing.T, r [][]string) [][]string {
			setExcelHostCell(t, r, "ssl", "bad")
			setExcelHostCell(t, r, "remote_port", "bad")
			return r
		}, true, "Ssl"},
		{"without_base_column", func(t *testing.T, r [][]string) [][]string { return [][]string{r[0][1:], r[1][1:]} }, false, ""},
		{"missing_model_column", func(t *testing.T, r [][]string) [][]string {
			for i, field := range r[0] {
				if field == "emergency_until" {
					return [][]string{append(r[0][:i], r[0][i+1:]...), append(r[1][:i], r[1][i+1:]...)}
				}
			}
			t.Fatal("emergency_until column missing")
			return nil
		}, true, "EmergencyUntil"},
		{"extra_nonempty_cell", func(t *testing.T, r [][]string) [][]string { r[1] = append(r[1], "extra"); return r }, true, ""},
		{"duplicate_header", func(t *testing.T, r [][]string) [][]string {
			r[0] = append(r[0], "emergency_until")
			r[1] = append(r[1], "0")
			return r
		}, true, "EmergencyUntil"},
		{"reordered_columns", func(t *testing.T, r [][]string) [][]string {
			for i, j := 0, len(r[0])-1; i < j; i, j = i+1, j-1 {
				r[0][i], r[0][j] = r[0][j], r[0][i]
				r[1][i], r[1][j] = r[1][j], r[1][i]
			}
			return r
		}, false, ""},
		{"trailing_empty_string", func(t *testing.T, r [][]string) [][]string {
			for i, field := range r[0] {
				if field == "remarks" {
					r[0][i], r[0][len(r[0])-1] = r[0][len(r[0])-1], r[0][i]
					r[1][i] = r[1][len(r[1])-1]
					r[1] = r[1][:len(r[1])-1]
					return r
				}
			}
			t.Fatal("remarks column missing")
			return nil
		}, false, ""},
		{"empty_workbook", func(t *testing.T, r [][]string) [][]string { return nil }, true, ""},
		{"blank_row", func(t *testing.T, r [][]string) [][]string { return [][]string{r[0], {}, r[1]} }, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupNotifyTestEnv(t, &model.Hosts{})
			host := excelHostFixture(t)
			rows := tc.edit(t, excelHostRows(host))
			result := waf_service.ImportHostsExcel(rows, "1")
			var count int64
			if err := global.GWAF_LOCAL_DB.Model(&model.Hosts{}).Count(&count).Error; err != nil {
				t.Fatal(err)
			}
			if tc.fail {
				if result.SuccessInt != 0 || result.FailInt != 1 || count != 0 || !strings.Contains(result.Msg, tc.message) {
					t.Fatalf("invalid import must fail once without insertion: %+v, count=%d", result, count)
				}
				return
			}
			if result.SuccessInt != 1 || result.FailInt != 0 || result.Msg != "" || count != 1 {
				t.Fatalf("valid import failed: %+v count=%d", result, count)
			}
			if tc.name == "int64_zero" {
				host.EmergencyUntil = 0
			}
			if tc.name == "int64_max" {
				host.EmergencyUntil = 9223372036854775807
			}
			if tc.name == "trailing_empty_string" {
				host.REMARKS = ""
			}
			assertExcelImportedHost(t, host, "1")
		})
	}
}

func TestHostsExcelImportDuplicatesAndBatch(t *testing.T) {
	for _, duplicate := range []string{"code", "host_port"} {
		t.Run(duplicate, func(t *testing.T) {
			setupNotifyTestEnv(t, &model.Hosts{})
			host := excelHostFixture(t)
			existing := host
			if duplicate == "code" {
				existing.Host = "other.example"
			} else {
				existing.Code = "other-code"
			}
			if err := global.GWAF_LOCAL_DB.Create(&existing).Error; err != nil {
				t.Fatal(err)
			}
			result := waf_service.ImportHostsExcel(excelHostRows(host), "1")
			if result.FailInt != 1 || result.SuccessInt != 0 {
				t.Fatalf("duplicate accepted: %+v", result)
			}
		})
	}
	t.Run("invalid_row_then_valid", func(t *testing.T) {
		setupNotifyTestEnv(t, &model.Hosts{})
		host := excelHostFixture(t)
		rows := excelHostRows(host)
		valid := append([]string(nil), rows[1]...)
		setExcelHostCell(t, rows, "emergency_until", "invalid")
		rows = append(rows, valid)
		result := waf_service.ImportHostsExcel(rows, "1")
		if result.SuccessInt != 1 || result.FailInt != 1 || !strings.Contains(result.Msg, "2") {
			t.Fatalf("batch accounting incorrect: %+v", result)
		}
		assertExcelImportedHost(t, host, "1")
	})
}

func TestHostsExcelImportBadRequests(t *testing.T) {
	for _, tc := range []struct {
		name, table, strategy string
		file                  bool
	}{
		{"no_file", "hosts", "0", false},
		{"no_table", "", "0", true},
		{"unknown_table", "unknown", "0", true},
		{"no_strategy", "hosts", "", true},
		{"unknown_strategy", "hosts", "2", true},
		{"invalid_workbook", "hosts", "0", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := importExcelRequest(t, []byte("invalid workbook"), tc.table, tc.strategy, tc.file)
			if rec.Code != http.StatusBadRequest || rec.Body.Len() == 0 {
				t.Fatalf("want explained HTTP400, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestGetColumnName(t *testing.T) {
	api := new(WafCommonApi)
	for index, want := range map[int]string{0: "A", 25: "Z", 26: "AA", 51: "AZ", 52: "BA", 500: "SG"} {
		if got := api.GetColumnName(index); got != want {
			t.Errorf("column %s: want %s, got %s", strconv.Itoa(index), want, got)
		}
	}
}
