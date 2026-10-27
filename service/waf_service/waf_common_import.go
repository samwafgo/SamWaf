package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
	"time"
)

type ReturnImportData struct {
	SuccessInt int
	FailInt    int
	Msg        string
}

// ImportHostsExcel 导入包含完整 Hosts 表头的网站数据。
func ImportHostsExcel(rows [][]string, importCodeStrategy string) ReturnImportData {
	var result ReturnImportData
	if importCodeStrategy != "0" && importCodeStrategy != "1" {
		result.FailInt = 1
		result.Msg = "导入策略无效，仅支持 0 或 1"
		return result
	}
	processImportData(rows, importCodeStrategy, &result)
	return result
}

func processImportData(rows [][]string, strategy string, result *ReturnImportData) {
	if len(rows) == 0 {
		result.FailInt = 1
		result.Msg = "行 1, 缺少表头 |"
		return
	}
	typ := reflect.TypeOf(model.Hosts{})
	columns := make(map[string]int)
	for column, name := range rows[0] {
		if name == " - " || name == "" {
			continue
		}
		if _, exists := columns[name]; exists {
			// 只输出模型字段信息，不回显表头文本。
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				if field.Name != "BaseOrm" && field.Tag.Get("json") == name {
					result.FailInt = 1
					result.Msg = fmt.Sprintf("行 1, 字段 %s (%s) 表头重复 |", field.Name, field.Type)
					return
				}
			}
			result.FailInt = 1
			result.Msg = fmt.Sprintf("行 1, 第 %d 列表头重复 |", column+1)
			return
		}
		columns[name] = column
	}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.Name == "BaseOrm" {
			continue
		}
		if _, exists := columns[field.Tag.Get("json")]; !exists {
			result.FailInt = 1
			result.Msg = fmt.Sprintf("行 1, 缺少字段 %s (%s) 表头 |", field.Name, field.Type)
			return
		}
	}

	for index, row := range rows[1:] {
		rowNumber := index + 2
		if importRowEmpty(row) {
			continue
		}
		var rowErr error
		for column := len(rows[0]); column < len(row); column++ {
			if strings.TrimSpace(row[column]) != "" {
				rowErr = fmt.Errorf("第 %d 列超出表头范围", column+1)
				break
			}
		}
		if rowErr != nil {
			result.addRowFailure(rowNumber, rowErr)
			continue
		}
		hostName := importCell(row, columns["host"])
		if strings.TrimSpace(hostName) == "" || hostName == "全局网站" {
			continue
		}

		var host model.Hosts
		value := reflect.ValueOf(&host).Elem()
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if field.Name == "BaseOrm" {
				continue
			}
			if err := setImportScalar(value.Field(i), importCell(row, columns[field.Tag.Get("json")])); err != nil {
				rowErr = fmt.Errorf("字段 %s (%s) %s", field.Name, field.Type, err)
				break
			}
		}
		if rowErr != nil {
			result.addRowFailure(rowNumber, rowErr)
			continue
		}
		if strategy == "0" {
			host.Code = uuid.GenUUID()
		} else if err := checkHostCodeData(host.Code); err != nil {
			result.addRowFailure(rowNumber, err)
			continue
		}
		if err := checkHostPortData(host.Host, host.Port); err != nil {
			result.addRowFailure(rowNumber, err)
			continue
		}
		now := customtype.JsonTime(time.Now())
		host.BaseOrm = baseorm.BaseOrm{
			Id: uuid.GenUUID(), USER_CODE: global.GWAF_USER_CODE, Tenant_ID: global.GWAF_TENANT_ID,
			CREATE_TIME: now, UPDATE_TIME: now,
		}
		if err := global.GWAF_LOCAL_DB.Create(&host).Error; err != nil {
			result.addRowFailure(rowNumber, errors.New("插入失败"))
			continue
		}
		result.SuccessInt++
	}
}

func (r *ReturnImportData) addRowFailure(rowNumber int, err error) {
	r.FailInt++
	r.Msg += fmt.Sprintf("行 %d, %s |", rowNumber, err)
}

func importCell(row []string, column int) string {
	if column >= len(row) {
		return ""
	}
	return row[column]
}

func importRowEmpty(row []string) bool {
	for _, cell := range row {
		if strings.TrimSpace(cell) != "" {
			return false
		}
	}
	return true
}

// setImportScalar 转换成功后才写入字段；错误不包含单元格内容。
func setImportScalar(field reflect.Value, text string) error {
	if !field.IsValid() || !field.CanSet() {
		return errors.New("字段不可写")
	}
	switch field.Kind() {
	case reflect.String:
		field.SetString(text)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, err := strconv.ParseInt(text, 10, field.Type().Bits())
		if err != nil {
			return errors.New("整数无效或超出范围")
		}
		field.SetInt(n)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		n, err := strconv.ParseUint(text, 10, field.Type().Bits())
		if err != nil {
			return errors.New("无符号整数无效或超出范围")
		}
		field.SetUint(n)
	case reflect.Bool:
		b, err := strconv.ParseBool(text)
		if err != nil {
			return errors.New("布尔值无效")
		}
		field.SetBool(b)
	case reflect.Float32, reflect.Float64:
		n, err := strconv.ParseFloat(text, field.Type().Bits())
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
			return errors.New("浮点数无效或超出范围")
		}
		field.SetFloat(n)
	default:
		return errors.New("不支持的字段类型")
	}
	return nil
}

func checkHostCodeData(code string) error {
	var count int64
	if global.GWAF_LOCAL_DB == nil || global.GWAF_LOCAL_DB.Model(&model.Hosts{}).Where("code = ?", code).Count(&count).Error != nil {
		return errors.New("字段 Code (string) 重复检查失败")
	}
	if count > 0 {
		return errors.New("字段 Code (string) 数据已存在不进行插入")
	}
	return nil
}

func checkHostPortData(host string, port int) error {
	var count int64
	if global.GWAF_LOCAL_DB == nil || global.GWAF_LOCAL_DB.Model(&model.Hosts{}).Where("host = ? AND port = ?", host, port).Count(&count).Error != nil {
		return errors.New("字段 Host (string) + Port (int) 重复检查失败")
	}
	if count > 0 {
		return errors.New("字段 Host (string) + Port (int) 数据已存在不进行插入")
	}
	return nil
}
