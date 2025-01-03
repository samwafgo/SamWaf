package codetemplete

import (
	"SamWaf/utils"
	"bytes"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"text/template"
	"unicode"
)

// getStructFields 拉平解析结构体的字段信息，支持嵌套结构体
func GetStructFields(t interface{}) []map[string]string {
	var fields []map[string]string
	typ := reflect.TypeOf(t)

	// 确保输入的是结构体
	if typ.Kind() == reflect.Struct {
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			// 如果字段是嵌套结构体，递归解析子模型
			if field.Type.Kind() == reflect.Struct && field.Type.String() != "time.Time" {
				//fmt.Printf("field.Type.String():" + field.Type.String())
				subFields := GetStructFields(reflect.New(field.Type).Elem().Interface())
				fields = append(fields, subFields...)
			} else {
				// 普通字段
				if field.Name == "wall" || field.Name == "ext" || field.Name == "loc" {
					continue
				}
				fields = append(fields, map[string]string{
					"Name": field.Name,
					"Type": field.Type.String(),
					"Tag":  string(field.Tag),
				})
			}
		}
	}
	return fields
}
func initFunc() template.FuncMap {
	return template.FuncMap{
		"lower": func(s string) string {
			return string(bytes.ToLower([]byte(s)))
		},
		"pascalCase": func(s string) string {
			// 将字符串转换为首字母大写格式（PascalCase）
			words := strings.Fields(s) // 按空格分割单词
			for i := range words {
				// 对每个单词的首字母进行大写
				words[i] = strings.Title(words[i])
			}
			// 连接成一个字符串并返回
			return strings.Join(words, "")
		},
		"unescapeHtml": func(s string) string {
			return html.UnescapeString(s)
		},
		"addForm": func(s string) string {
			return strings.ReplaceAll(s, "json:", "form:")
		},
		"snakeCase": func(s string) string {
			// 将字符串转换为小写并替换大写字母为下划线连接的小写字母
			var result []rune
			for i, r := range s {
				// 如果是大写字母且不是第一个字符，前面加下划线
				if unicode.IsUpper(r) {
					if i > 0 {
						result = append(result, '_')
					}
					// 转换为小写
					result = append(result, unicode.ToLower(r))
				} else {
					result = append(result, r)
				}
			}
			return string(result)
		},
		"removeQuotes": func(s string) string {
			// 去掉字符串中的引号
			return strings.ReplaceAll(s, `"`, "")
		},
	}
}

// renderTemplateAndSave 用于渲染模板并保存到指定路径
// templatePath：模板文件的路径
// renderData：传递给模板的数据
// outputPath 路径
// outputPathTemplate：输出文件的保存文件模板
// isDefaultDelim 是否默认模板分隔符
func renderTemplateAndSave(templatePath string, renderData map[string]interface{}, outputPath string, outputPathTemplate string, isDefaultDelim bool) error {
	// 读取模板文件
	templateContent, err := os.ReadFile(templatePath)
	if err != nil {
		return fmt.Errorf("读取模板文件失败: %v", err)
	}

	// 如果 isDefaultDelim 为 false，使用自定义分隔符
	var tmpl *template.Template
	if isDefaultDelim {
		// 使用默认分隔符
		tmpl, err = template.New("apiTemplate").Funcs(initFunc()).Parse(string(templateContent))
	} else {
		// 使用自定义分隔符，防止与 Vue 模板冲突
		tmpl, err = template.New("vueTemplate").Delims("[[", "]]").Funcs(initFunc()).Parse(string(templateContent))
	}

	if err != nil {
		return fmt.Errorf("解析模板失败: %v", err)
	}

	// 渲染模板
	var renderedCode bytes.Buffer
	if isDefaultDelim {
		err = tmpl.Execute(&renderedCode, renderData)
		if err != nil {
			return fmt.Errorf("渲染模板失败: %v", err)
		}
	} else {
		err = tmpl.ExecuteTemplate(&renderedCode, "vueTemplate", renderData)
		if err != nil {
			return fmt.Errorf("渲染模板失败: %v", err)
		}
	}

	// 解码HTML实体字符
	//decodedCode := html.UnescapeString(renderedCode.String())

	/*fmt.Println("Before Rendered Code:")
	fmt.Println(renderedCode)
	fmt.Println("Decoded Rendered Code:")
	fmt.Println(decodedCode)*/

	// 渲染输出路径
	utils.CheckPathAndCreate(outputPath)

	outputPathTemplateParsed, err := template.New("outputPath").Funcs(initFunc()).Parse(outputPathTemplate)
	if err != nil {
		return fmt.Errorf("解析输出路径模板失败: %v", err)
	}

	var outputPathBuffer bytes.Buffer
	err = outputPathTemplateParsed.Execute(&outputPathBuffer, renderData)
	if err != nil {
		return fmt.Errorf("渲染输出路径失败: %v", err)
	}

	// 输出到指定文件
	outputPathFinal := filepath.Join(outputPath, outputPathBuffer.String())
	err = os.WriteFile(outputPathFinal, renderedCode.Bytes(), 0644)
	if err != nil {
		return fmt.Errorf("写入输出文件失败: %v", err)
	}

	fmt.Printf("代码生成成功，已保存到 %s\n", outputPathFinal)
	return nil
}

func CodeGeneration(entityName string, fields []map[string]string, uniFields []map[string]string) {
	fmt.Printf("%v\n", fields)
	fmt.Printf("%v\n", uniFields)
	// 打印当前工作目录
	/*	currentDir, err := os.Getwd()
		fmt.Println(currentDir)*/
	// 生成api
	err := renderTemplateAndSave("./tpl/waf_api.txt", map[string]interface{}{
		"EntityName": entityName, // 需要替换的实体名称
		"Fields":     fields,
		"UniFields":  uniFields, //唯一识别的字段
	}, "./output/"+entityName+"/api/", "waf_{{.EntityName | lower}}_api.go", true)
	if err != nil {
		fmt.Printf("生成代码失败: %v\n", err)
	}

	// 生成service
	err = renderTemplateAndSave("./tpl/waf_service.txt", map[string]interface{}{
		"EntityName": entityName, // 需要替换的实体名称
		"Fields":     fields,
		"UniFields":  uniFields, //唯一识别的字段
	}, "./output/"+entityName+"/service/", "waf_{{.EntityName | lower}}_service.go", true)
	if err != nil {
		fmt.Printf("生成代码失败: %v\n", err)
	}

	// 生成req
	err = renderTemplateAndSave("./tpl/waf_req.txt", map[string]interface{}{
		"EntityName": entityName, // 需要替换的实体名称
		"Fields":     fields,
		"UniFields":  uniFields, //唯一识别的字段
	}, "./output/"+entityName+"/request/", "waf_{{.EntityName | lower}}_req.go", true)
	if err != nil {
		fmt.Printf("生成代码失败: %v\n", err)
	}

	// 生成router
	err = renderTemplateAndSave("./tpl/waf_router.txt", map[string]interface{}{
		"EntityName": entityName, // 需要替换的实体名称
		"Fields":     fields,
		"UniFields":  uniFields, //唯一识别的字段
	}, "./output/"+entityName+"/router/", "waf_{{.EntityName | lower}}_router.go", true)
	if err != nil {
		fmt.Printf("生成代码失败: %v\n", err)
	}
	// 生成vue
	err = renderTemplateAndSave("./tpl/index_vue.txt", map[string]interface{}{
		"EntityName": entityName, // 需要替换的实体名称
		"Fields":     fields,
		"UniFields":  uniFields, //唯一识别的字段
	}, "./output/"+entityName+"/vue/", "index.vue", false)
	if err != nil {
		fmt.Printf("生成代码失败: %v\n", err)
	}
	// 生成js api
	err = renderTemplateAndSave("./tpl/index_jsapi.txt", map[string]interface{}{
		"EntityName": entityName, // 需要替换的实体名称
		"Fields":     fields,
		"UniFields":  uniFields, //唯一识别的字段
	}, "./output/"+entityName+"/vue/", "{{.EntityName | snakeCase}}.ts", true)
	if err != nil {
		fmt.Printf("生成代码失败: %v\n", err)
	}

	// 生成语言文件
	err = renderTemplateAndSave("./tpl/index_zh_en.txt", map[string]interface{}{
		"EntityName": entityName, // 需要替换的实体名称
		"Fields":     fields,
		"UniFields":  uniFields, //唯一识别的字段
	}, "./output/"+entityName+"/vue/", "{{.EntityName | snakeCase}}_zh_en.ts", false)
	if err != nil {
		fmt.Printf("生成代码失败: %v\n", err)
	}
}
