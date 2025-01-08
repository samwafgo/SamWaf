package codetemplete

import (
	"SamWaf/model"
	"strings"
	"testing"
)

func TestCodeGeneration(t *testing.T) {
	// 定义字段信息的字符串
	fieldDefs := []string{
		"TaskName:task_name:string",
	}

	// 构造 `uniFields` 列表
	uniFields := []map[string]string{}
	for _, fieldDef := range fieldDefs {
		// 解析每个字段定义
		parts := strings.Split(fieldDef, ":")
		if len(parts) == 3 {
			field := map[string]string{
				"Name":     parts[0],
				"SqlField": parts[1],
				"SqlType":  parts[2],
			}
			uniFields = append(uniFields, field)
		}
	}

	fields := GetStructFields(model.Task{})
	CodeGeneration("Task", fields, uniFields)
}
