package api

import (
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"fmt"
	"github.com/360EntSecGroup-Skylar/excelize"
	"github.com/gin-gonic/gin"
	"log"
	"reflect"
	"time"
)

type WafCommonApi struct {
}

// 导出excel
func (w *WafCommonApi) ExportExcelApi(c *gin.Context) {
	var req request.WafCommonReq
	err := c.ShouldBind(&req)
	if err == nil {
		// 生成文件名
		fileName := time.Now().Format("20060102150405") + ".xlsx"

		// 创建 Excel 文件
		f := excelize.NewFile()
		sheetName := "Sheet1"
		// 获取数据的类型和值
		dataType, dataValue := getStructTypeValueByName(req.TableName)

		/*dataType := reflect.TypeOf(data)
		dataValue := reflect.ValueOf(data)*/

		// 设置表头
		for i := 0; i < dataType.NumField(); i++ {
			field := dataType.Field(i)
			colName := field.Tag.Get("json") // 获取 excel 标签的值，即表头名称
			f.SetCellValue(sheetName, fmt.Sprintf("%c%d", 'A'+i, 1), colName)
		}

		// 填充数据
		for i := 0; i < dataValue.Len(); i++ {
			rowNum := i + 2
			rowValue := dataValue.Index(i)
			for j := 0; j < dataType.NumField(); j++ {
				colValue := rowValue.Field(j).Interface()
				f.SetCellValue(sheetName, fmt.Sprintf("%c%d", 'A'+j, rowNum), colValue)
			}
		}

		// 保存 Excel 文件
		if err := f.SaveAs(fileName); err != nil {
			log.Fatal("无法保存 Excel 文件：", err)
		}

		// 设置响应头
		c.Header("Content-Type", "application/octet-stream")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))

		// 将文件内容输出给客户端
		c.File(fileName)
		// 删除临时文件
		/*if err := os.Remove(fileName); err != nil {
			log.Println("无法删除临时文件：", err)
		}*/
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// 获取结构体类型通过名称
func getStructTypeValueByName(name string) (reflect.Type, reflect.Value) {
	switch name {
	case "hosts":
		// 模拟获取数据
		webHosts := []model.Hosts{
			{Host: "www.baidu1.com"},
			{Host: "www.baidu2.com"},
		}
		return reflect.TypeOf(model.Hosts{}), reflect.ValueOf(webHosts)
	default:
		return nil, reflect.ValueOf(nil)
	}
}
