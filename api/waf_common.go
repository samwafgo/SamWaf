package api

import (
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/service/waf_service"
	"fmt"
	"log"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/xuri/excelize/v2"
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
			if field.Name == "BaseOrm" {
				f.SetCellValue(sheetName, fmt.Sprintf("%s%d", w.GetColumnName(i), 1), " - ")
			} else {
				colName := field.Tag.Get("json") // 获取 excel 标签的值，即表头名称
				//fmt.Println(fmt.Sprintf("%v ， %v  %v  %v", i, colName, dataType.NumField(), fmt.Sprintf("%s%d", w.GetColumnName(i), 1)))
				f.SetCellValue(sheetName, fmt.Sprintf("%s%d", w.GetColumnName(i), 1), colName)
			}
		}

		// 填充数据
		for i := 0; i < dataValue.Len(); i++ {
			rowNum := i + 2
			rowValue := dataValue.Index(i)
			for j := 0; j < dataType.NumField(); j++ {
				field := dataType.Field(j)
				if field.Name == "BaseOrm" {
					f.SetCellValue(sheetName, fmt.Sprintf("%s%d", w.GetColumnName(j), rowNum), "")
				} else {
					value := rowValue.Field(j)
					colValue := value.Interface()
					// Excel 数值仅保留 15 位有效数字，大整数使用文本单元格。
					switch value.Kind() {
					case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
						if n := value.Int(); n > 999999999999999 || n < -999999999999999 {
							colValue = strconv.FormatInt(n, 10)
						}
					case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
						if n := value.Uint(); n > 999999999999999 {
							colValue = strconv.FormatUint(n, 10)
						}
					}
					f.SetCellValue(sheetName, fmt.Sprintf("%s%d", w.GetColumnName(j), rowNum), colValue)
				}
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
		if err := os.Remove(fileName); err != nil {
			log.Println("无法删除临时文件：", err)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafCommonApi) ImportExcelApi(c *gin.Context) {
	importTable, ok := c.GetPostForm("import_table")
	if !ok || importTable != "hosts" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "import_table 仅支持 hosts"})
		return
	}
	importCodeStrategy, ok := c.GetPostForm("import_code_strategy")
	if !ok || (importCodeStrategy != "0" && importCodeStrategy != "1") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "import_code_strategy 仅支持 0 或 1"})
		return
	}
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "读取上传文件失败"})
		return
	}
	reader, err := file.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "打开上传文件失败"})
		return
	}
	defer reader.Close()
	f, err := excelize.OpenReader(reader)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "解析 Excel 文件失败"})
		return
	}
	defer f.Close()
	rows, err := f.GetRows("Sheet1", excelize.Options{RawCellValue: true})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "读取 Sheet1 失败"})
		return
	}
	ret := waf_service.ImportHostsExcel(rows, importCodeStrategy)
	response.OkWithDetailed(ret, "上传完成", c)
}

// 获取结构体类型通过名称
func getStructTypeValueByName(name string) (reflect.Type, reflect.Value) {
	switch name {
	case "hosts":
		// 模拟获取数据
		webHosts := wafHostService.GetAllHostApi()
		return reflect.TypeOf(model.Hosts{}), reflect.ValueOf(webHosts)
	case "ipblock":
		// 获取所有IP黑名单数据
		ipBlocks := wafIpBlockService.GetAllBlockIpApi()
		return reflect.TypeOf(model.IPBlockList{}), reflect.ValueOf(ipBlocks)
	default:
		return nil, reflect.ValueOf(nil)
	}
}
func (w *WafCommonApi) GetColumnName(colIdx int) string {
	// 英文字母有26个，列号超过26时使用多字母
	colName := ""
	for colIdx >= 0 {
		colName = fmt.Sprintf("%c", 'A'+colIdx%26) + colName
		colIdx = colIdx/26 - 1
	}
	return colName
}

// HeartbeatApi 心跳数据
func (w *WafCommonApi) HeartbeatApi(c *gin.Context) {
	response.Ok(c)
}
