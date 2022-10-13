package test

import (
	"SamWaf/innerbean"
	"github.com/hyperjumptech/grule-rule-engine/ast"
	"github.com/hyperjumptech/grule-rule-engine/builder"
	"github.com/hyperjumptech/grule-rule-engine/engine"
	"github.com/hyperjumptech/grule-rule-engine/pkg"
	"github.com/stretchr/testify/assert"
	"log"
	"testing"
)

func TestGrule(t *testing.T) {
	myFact := &innerbean.WebLog{
		SRC_IP: "127.0.0.1",
	}
	dataCtx := ast.NewDataContext()
	err := dataCtx.Add("MF", myFact)
	assert.NoError(t, err)

	// Prepare knowledgebase library and load it with our rule.
	knowledgeLibrary := ast.NewKnowledgeLibrary()
	ruleBuilder := builder.NewRuleBuilder(knowledgeLibrary)

	drls := `

rule R77a9d95d14624d4baaa9ef7af3061404 "试试344" salience 10 {
    when 
        MF.SRC_IP == "127.0.0.1"
    then
        
		Retract("R77a9d95d14624d4baaa9ef7af3061404");
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
rule R77a9d95d14624d4baaa9ef7af3061404 "试试344" salience 10 {
    when 
        MF.SRC_IP == "127.0.0.1"
    then
        
		Retract("R77a9d95d14624d4baaa9ef7af3061404");
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
