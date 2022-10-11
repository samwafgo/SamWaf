package test

import (
	"github.com/hyperjumptech/grule-rule-engine/ast"
	"github.com/hyperjumptech/grule-rule-engine/builder"
	"github.com/hyperjumptech/grule-rule-engine/engine"
	"github.com/hyperjumptech/grule-rule-engine/pkg"
	"github.com/stretchr/testify/assert"
	"log"
	"testing"
	"time"
)

func TestGrule(t *testing.T) {
	myFact := &MyFact{
		IntAttribute:     123,
		StringAttribute:  "Some string value",
		BooleanAttribute: true,
		FloatAttribute:   1.234,
		TimeAttribute:    time.Now(),
	}
	dataCtx := ast.NewDataContext()
	err := dataCtx.Add("MF", myFact)
	assert.NoError(t, err)

	// Prepare knowledgebase library and load it with our rule.
	knowledgeLibrary := ast.NewKnowledgeLibrary()
	ruleBuilder := builder.NewRuleBuilder(knowledgeLibrary)

	drls := `
rule CheckValues1 "Check the default values1牛啊" salience 10 {
    when 
        MF.IntAttribute == 1231 && MF.StringAttribute == "Some string value"
    then
        MF.WhatToSay = MF.GetWhatToSay("你好"); 
}
rule CheckValues2 "Check the default values2绝壁" salience 10 {
    when 
        MF.IntAttribute > 120
    then
        MF.WhatToSay = MF.GetWhatToSay("你好1"); 
}
`

	byteArr := pkg.NewBytesResource([]byte(drls))
	err = ruleBuilder.BuildRuleFromResource("Tutorial", "0.0.1", byteArr)
	assert.NoError(t, err)

	knowledgeBase := knowledgeLibrary.NewKnowledgeBaseInstance("Tutorial", "0.0.1")

	my_engine := engine.NewGruleEngine()
	processType := "match"
	if processType == "match" {
		matchrules, err := my_engine.FetchMatchingRules(dataCtx, knowledgeBase)
		if err != nil {
			log.Fatal(err)
		} else {
			log.Println(myFact.WhatToSay)
			log.Println(len(matchrules))
			for _, v := range matchrules {
				log.Println(v.RuleName)

				log.Println(v.RuleDescription)
			}
		}
	} else {
		err := my_engine.Execute(dataCtx, knowledgeBase)
		if err != nil {
			log.Fatal(err)
		}
	}

	//模拟动态新加的
	knowledgeLibrary = ast.NewKnowledgeLibrary()
	ruleBuilder = builder.NewRuleBuilder(knowledgeLibrary)
	drls = `
rule CheckValues1 "Check the default values1" salience 10 {
    when 
        MF.IntAttribute == 1231 && MF.StringAttribute == "Some string value"
    then
        MF.WhatToSay = MF.GetWhatToSay("你好"); 
}
rule CheckValues2 "Check the default values2" salience 10 {
    when 
        MF.IntAttribute > 120
    then
        MF.WhatToSay = MF.GetWhatToSay("你好1"); 
}
rule CheckValues3 "nihao" salience 10 {
    when 
        MF.IntAttribute > 0
    then
        MF.WhatToSay = MF.GetWhatToSay("你好1"); 
}
`

	byteArr = pkg.NewBytesResource([]byte(drls))
	err = ruleBuilder.BuildRuleFromResource("Tutorial", "0.0.1", byteArr)
	assert.NoError(t, err)

	knowledgeBase = knowledgeLibrary.NewKnowledgeBaseInstance("Tutorial", "0.0.1")

	my_engine = engine.NewGruleEngine()
	processType = "match"
	if processType == "match" {
		matchrules, err := my_engine.FetchMatchingRules(dataCtx, knowledgeBase)
		if err != nil {
			log.Fatal(err)
		} else {
			log.Println(myFact.WhatToSay)
			log.Println(len(matchrules))
			for _, v := range matchrules {
				log.Println(v.RuleName)
			}
		}
	} else {
		err := my_engine.Execute(dataCtx, knowledgeBase)
		if err != nil {
			log.Fatal(err)
		}
	}

}
