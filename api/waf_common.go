package api

import (
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"errors"
	"fmt"
	"github.com/360EntSecGroup-Skylar/excelize"
	"github.com/gin-gonic/gin"
	uuid "github.com/satori/go.uuid"
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
					colValue := rowValue.Field(j).Interface()
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
	importTable, succResult := c.GetPostForm("import_table")
	if !succResult {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}
	importCodeStrategy, succResult := c.GetPostForm("import_code_strategy")
	if !succResult {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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
	ret := saveDataToDatabase(importTable, rows, importCodeStrategy)
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
func (w *WafCommonApi) GetColumnName(colIdx int) string {
	// 英文字母有26个，列号超过26时使用多字母
	colName := ""
	for colIdx >= 0 {
		colName = fmt.Sprintf("%c", 'A'+colIdx%26) + colName
		colIdx = colIdx/26 - 1
	}
	return colName
}

// 通用数据插入函数
func saveDataToDatabase(tableName string, rows [][]string, importCodeStrategy string) ReturnImportData {
	successInt := 0
	failInt := 0
	msg := ""

	processImportData(&model.Hosts{}, tableName, rows, &successInt, &failInt, &msg, importCodeStrategy)

	return ReturnImportData{
		SuccessInt: successInt,
		FailInt:    failInt,
		Msg:        msg,
	}
}

// processImportData 是通用的导入数据函数
func processImportData(dataType interface{}, tableName string, rows [][]string, successInt, failInt *int, msg *string, importCodeStrategy string) {
	var header []string
	needJumpFristCol := false
	rowNumber := 0
	var dataMap map[string]string

	// 获取结构体类型和字段信息
	dataValue := reflect.ValueOf(dataType).Elem()
	dataTypeFields := dataValue.Type()

	// 获取表头
	for _, row := range rows {
		for _, colCell := range row {
			if colCell == " - " {
				needJumpFristCol = true
				continue
			}
			header = append(header, colCell)
		}
		break
	}

	// 处理数据 获取数据并插入数据库
	for _, row := range rows {
		if rowNumber == 0 && needJumpFristCol {
			rowNumber++
			continue
		}

		// 建立一个 map 来存储数据
		dataMap = make(map[string]string)
		colNumber := 0
		for _, colCell := range row {
			if colNumber == 0 && needJumpFristCol {
				colNumber++
				continue
			}
			headerNumber := colNumber
			if needJumpFristCol {
				headerNumber = headerNumber - 1
			}
			dataMap[header[headerNumber]] = colCell
			colNumber++
		}

		// 动态创建结构体实例，并映射数据
		newInstance := reflect.New(dataValue.Type()).Elem()

		for fieldIdx := 0; fieldIdx < dataTypeFields.NumField(); fieldIdx++ {
			field := dataTypeFields.Field(fieldIdx)
			fieldName := field.Name
			jsonTag := field.Tag.Get("json")

			// 如果 dataMap 中有匹配的字段
			if val, exists := dataMap[jsonTag]; exists {
				//排除一些特定数据
				if tableName == "hosts" && fieldName == "Host" && val == "全局网站" {
					continue
				}
				//检查数据是否已经存在
				if tableName == "hosts" && fieldName == "Host" {
					if importCodeStrategy == "1" {
						errMsg, err := checkHostCodeData(dataMap["code"])
						if err != nil {
							*msg += fmt.Sprintf("行 %d, 检测数据合法性时候 出错: %v |", rowNumber, errMsg)
							*failInt++
							continue
						}
					}
					errMsg, err := checkHostPortData(dataMap["host"], dataMap["port"])
					if err != nil {
						*msg += fmt.Sprintf("行 %d, 检测数据合法性时候 出错: %v |", rowNumber, errMsg)
						*failInt++
						continue
					}
				}
				// 将字段值设置到结构体中
				fieldVal := newInstance.Field(fieldIdx)
				// 转换并设置字段的值
				switch fieldVal.Kind() {
				case reflect.String:
					if tableName == "hosts" {
						if importCodeStrategy == "0" && fieldName == "Code" {
							fieldVal.SetString(uuid.NewV4().String())
						} else {
							fieldVal.SetString(val)
						}
					} else {
						fieldVal.SetString(val)
					}
				case reflect.Int:
					intVal, err := strconv.Atoi(val)
					if err != nil {
						*msg += fmt.Sprintf("行 %d, 字段 %s 转换为 int 错误: %v |", rowNumber, fieldName, err)
						*failInt++
						continue
					}
					fieldVal.SetInt(int64(intVal))
				default:
					*msg += fmt.Sprintf("不支持的字段类型: %s |", fieldVal.Kind())
					*failInt++
				}
			} else if fieldName == "BaseOrm" {
				fieldVal := newInstance.Field(fieldIdx)
				// 给 BaseOrm 赋值
				baseOrm := baseorm.BaseOrm{
					Id:          uuid.NewV4().String(), // 新生成的 ID
					USER_CODE:   global.GWAF_USER_CODE,
					Tenant_ID:   global.GWAF_TENANT_ID,
					CREATE_TIME: customtype.JsonTime(time.Now()),
					UPDATE_TIME: customtype.JsonTime(time.Now()),
				}
				// 将 BaseOrm 设置到结构体字段
				fieldVal.Set(reflect.ValueOf(baseOrm))
			} else {
				*msg += fmt.Sprintf("行 %d, 缺少字段 %s 数据 |", rowNumber, fieldName)
				*failInt++
			}
		}
		if err := global.GWAF_LOCAL_DB.Create(newInstance.Interface()); err != nil {
			errGorm := err.Error
			if errGorm != nil {
				*msg += fmt.Sprintf("行 %d 插入失败: %v |", rowNumber, err.Error)
				*failInt++
			} else {
				*successInt++
			}
		}

		rowNumber++
	}
}

// checkHostData 检查host信息是否合法
func checkHostCodeData(code string) (string, error) {
	// 唯一性校验：检查 `Code` 是否已存在
	if wafHostService.GetDetailByCodeApi(code).Code != "" {
		errorMsg := "Code 数据已存在不进行插入"
		// 数据已存在，不插入
		return errorMsg, errors.New(errorMsg)
	}
	return "数据正常", nil
}
func checkHostPortData(host string, port string) (string, error) {
	//唯一性校验：检查 `Host` 和 `Port` 的组合是否已存在
	if err := wafHostService.CheckIsExist(host, port); err == nil {
		errorMsg := "Host+Port 数据已存在不进行插入"
		// 数据已存在，不插入
		return errorMsg, errors.New(errorMsg)
	}
	return "数据正常", nil
}
