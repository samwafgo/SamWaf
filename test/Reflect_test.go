package test

import (
	"SamWaf/model"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

func TestReflect(t *testing.T) {
	typeOfPerson := reflect.TypeOf(model.Hosts{})

	//遍历所有结构体成员获取字段信息
	fmt.Println("遍历结构体：")
	for i := 0; i < typeOfPerson.NumField(); i++ {
		field := typeOfPerson.Field(i)
		fmt.Printf("json%s\n", "{"+field.Tag+"}")
		var dataMap map[string]string
		err := json.Unmarshal([]byte("{"+field.Tag+"}"), &dataMap)
		if err != nil {
			fmt.Printf("Json串转化为Map失败,异常:%s\n", err)
			//return
		}
		//fmt.Printf("字段名：%v 字段标签：%v ，解析后的数据库值:%v  \n 是否匿名字段：%v \n", field.Name, field.Tag, dataMap["json"],field.Anonymous)
	}

	//通过字段名获取字段信息
	if field, ok := typeOfPerson.FieldByName("Age"); ok {
		fmt.Println("通过字段名")
		var dataMap map[string]string
		err := json.Unmarshal([]byte(field.Tag.Get("json")), &dataMap)
		if err != nil {
			fmt.Printf("Json串转化为Map失败,异常:%s\n", err)
			return
		}

		fmt.Printf("字段名：%v , 字段标签中json: %v ，解析后的数据库值:%v  \n ", field.Name, field.Tag.Get("json"), dataMap["json"])
	}

	//通过下标获取字段信息
	field := typeOfPerson.FieldByIndex([]int{1})
	fmt.Println("通过下标：")
	fmt.Printf("字段名：%v , 字段标签：%v \n", field.Name, field.Tag)
}
