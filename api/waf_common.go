package api

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"errors"
	"fmt"
	"github.com/360EntSecGroup-Skylar/excelize"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"log"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"time"
)

type WafCommonApi struct {
}
type ReturnImportData struct {
	SuccessInt int
	FailInt    int
	Msg        string
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
		if err := os.Remove(fileName); err != nil {
			log.Println("无法删除临时文件：", err)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafCommonApi) ImportExcelApi(c *gin.Context) {
	file, err := c.FormFile("file") // "excelFile" 对应前端上传的文件字段名
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// 生成文件名
	fileName := time.Now().Format("20060102150405") + "import.xlsx"

	if err := c.SaveUploadedFile(file, fileName); // 保存文件到指定路径
	err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 创建 Excel 文件
	f, err := excelize.OpenFile(fileName)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Get all the rows in the Sheet1.
	rows := f.GetRows("Sheet1")
	if err != nil {
		fmt.Println(err)
		return
	}
	ret := saveDataToDatabase("hosts", rows)
	// 删除临时文件
	if err := os.Remove(fileName); err != nil {
		log.Println("无法删除临时文件：", err)
	}
	response.OkWithDetailed(ret, "上传完成", c)
}

// 获取结构体类型通过名称
func getStructTypeValueByName(name string) (reflect.Type, reflect.Value) {
	switch name {
	case "hosts":
		// 模拟获取数据
		webHosts := wafHostService.GetAllHostApi()
		return reflect.TypeOf(model.Hosts{}), reflect.ValueOf(webHosts)
	default:
		return nil, reflect.ValueOf(nil)
	}
}

// 保存Excel数据
func saveDataToDatabase(name string, rows [][]string) ReturnImportData {
	successInt := 0
	failInt := 0
	msg := ""
	switch name {
	case "hosts":
		needJumpFristCol := false
		var header []string
		// 获取header
		for _, row := range rows {
			for _, colCell := range row {
				if colCell == " - " {
					needJumpFristCol = true
					continue
				}
				fmt.Print(colCell, "\t")
				header = append(header, colCell)
			}
			break
			fmt.Println()
		}
		fmt.Println("一下是数据")
		// 获取数据
		rowNumber := 0
		for _, row := range rows {
			if rowNumber == 0 && needJumpFristCol == true {
				rowNumber++
				continue
			}
			colNumber := 0
			data := make(map[string]string)
			//循环列
			for _, colCell := range row {

				if colNumber == 0 && needJumpFristCol == true {
					colNumber++
					continue
				}
				headerNumber := colNumber
				if needJumpFristCol == true {
					headerNumber = headerNumber - 1
				}
				data[header[headerNumber]] = colCell
				fmt.Println(header[headerNumber], ":", colCell, "\t")
				colNumber++
			}

			//准备插入数据
			if wafHostService.GetDetailByCodeApi(data["code"]).Code != "" {
				fmt.Println(data["code"], " 数据已存在不进行插入\t")
				msg += "行" + strconv.Itoa(rowNumber) + " code:" + data["code"] + " 数据已存在不进行插入 "
				failInt++
				rowNumber++
				continue
			}

			err := wafHostService.CheckIsExist(data["host"], data["port"])
			if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
				var wafHost = &model.Hosts{
					USER_CODE: global.GWAF_USER_CODE,
					Tenant_id: global.GWAF_TENANT_ID,
					Code:      data["code"],
					Host:      data["host"],
					/*Port:          data["port"],
					Ssl:           data["ssl"],
					GUARD_STATUS:  data["guard_status"],*/
					REMOTE_SYSTEM: data["remote_system"],
					REMOTE_APP:    data["remote_app"],
					Remote_host:   data["remote_host"],
					/*Remote_port:   data["remote_port"],*/
					Remote_ip:   data["remote_ip"],
					Certfile:    data["certfile"],
					Keyfile:     data["keyfile"],
					REMARKS:     data["remarks"],
					CREATE_TIME: time.Now(),
					UPDATE_TIME: time.Now(),
				}
				port, err := strconv.Atoi(data["port"])
				if err != nil {
					fmt.Println("转换出错:", err)
					msg += "行" + strconv.Itoa(rowNumber) + " port:" + data["port"] + " 转换出错 "
					failInt++
					continue
				}
				wafHost.Port = port
				ssl, err := strconv.Atoi(data["ssl"])
				if err != nil {
					fmt.Println("转换出错:", err)
					msg += "行" + strconv.Itoa(rowNumber) + " ssl:" + data["ssl"] + " 转换出错 "
					failInt++
					continue
				}
				wafHost.Ssl = ssl

				guard_status, err := strconv.Atoi(data["guard_status"])
				if err != nil {
					fmt.Println("转换出错:", err)
					msg += "行" + strconv.Itoa(rowNumber) + " guard_status:" + data["guard_status"] + " 转换出错 "
					failInt++
					continue
				}
				wafHost.GUARD_STATUS = guard_status

				remote_port, err := strconv.Atoi(data["remote_port"])
				if err != nil {
					fmt.Println("转换出错:", err)
					msg += "行" + strconv.Itoa(rowNumber) + " remote_port:" + data["remote_port"] + " 转换出错 "
					failInt++
					continue
				}
				wafHost.Remote_port = remote_port

				global.GWAF_LOCAL_DB.Create(wafHost)
				successInt++
			} else {
				failInt++
				msg += "行" + strconv.Itoa(rowNumber) + " host:" + data["host"] + " port:" + data["port"] + " 数据已存在不进行插入\t"
				fmt.Println(data["host"], data["port"], " 数据已存在不进行插入\t")
			}
			rowNumber++
			fmt.Println()
		}

	default:
	}

	return ReturnImportData{
		SuccessInt: successInt,
		FailInt:    failInt,
		Msg:        msg,
	}
}
