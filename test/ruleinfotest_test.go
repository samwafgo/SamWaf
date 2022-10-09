package test

import (
	"SamWaf/model/rule"
	"fmt"
	"testing"
)

func TestJsonTest(t *testing.T) {
	// str 在项目开发中，是通过网络传输获取到.. 或者是读取文件获取到
	//str := "{\n    \"rule_base\": {\n        \"salience\": 10,\n        \"rule_name\": \"试试\",\n        \"rule_domain_code\": \"CODDD\"\n    },\n    \"rule_condition_detail\": {\n        \"relation_detail\": [\n            {\n                \"fact_name\": \"MF\",\n                \"attr\": \"StringAttribute\",\n                \"attr_type\": \"string\",\n                \"attr_judge\": \"==\",\n                \"attr_val\": \"值\"\n            },\n            {\n                \"fact_name\": \"MF\",\n                \"attr\": \"IntAttribute\",\n                \"attr_type\": \"int\",\n                \"attr_judge\": \"==\",\n                \"attr_val\": \"0\"\n            }\n        ],\n        \"relation_symbol\": \"&&\"\n    },\n    \"rule_do_assignment\": [\n        {\n            \"fact_name\": \"MF\",\n            \"attr\": \"StringAttribute\",\n            \"attr_type\": \"string\",\n            \"attr_val\": \"值\"\n        },\n        {\n            \"fact_name\": \"MF\",\n            \"attr\": \"IntAttribute\",\n            \"attr_type\": \"int\",\n            \"attr_val\": \"0\"\n        }\n    ],\n    \"rule_do_method\": [\n        {\n            \"fact_name\": \"MF\",\n            \"method_name\": \"DoSomeThing\",\n            \"parms\": [\n                {\n                    \"attr_type\": \"string\",\n                    \"attr_val\": \"值\"\n                },\n                {\n                    \"attr_type\": \"string\",\n                    \"attr_val\": \"值\"\n                }\n            ]\n        }\n    ]\n}"
	str := "{\n    \"rule_base\": {\n        \"salience\": 10,\n        \"rule_name\": \"试试\",\n        \"rule_domain_code\": \"CODDD\"\n    },\n    \"rule_condition_detail\": {\n        \"relation_detail\": [\n            {\n                \"fact_name\": \"MF\",\n                \"attr\": \"StringAttribute\",\n                \"attr_type\": \"string\",\n                \"attr_judge\": \"==\",\n                \"attr_val\": \"值\"\n            },\n            {\n                \"fact_name\": \"MF\",\n                \"attr\": \"IntAttribute\",\n                \"attr_type\": \"int\",\n                \"attr_judge\": \"==\",\n                \"attr_val\": \"0\"\n            }\n        ],\n        \"relation_symbol\": \"&&\"\n    },\n    \"rule_do_assignment\": [\n         \n    ],\n    \"rule_do_method\": [\n         \n    ]\n}"

	var ruleTool rule.RuleTool
	ruleInfo, err := ruleTool.LoadRule(str)

	if err != nil {
		fmt.Printf("unmarshal err=%v\n", err)
	}
	fmt.Printf("反序列化后 RuleName=%v RuleDomainCode=%v \n", ruleInfo.RuleBase.RuleName, ruleInfo.RuleBase.RuleDomainCode)

	fmt.Println(ruleTool.GenRuleInfo(ruleInfo))
}
