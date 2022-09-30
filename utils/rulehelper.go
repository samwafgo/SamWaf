package utils

import (
	"SamWaf/innerbean"
	"github.com/hyperjumptech/grule-rule-engine/ast"
	"github.com/hyperjumptech/grule-rule-engine/builder"
	"github.com/hyperjumptech/grule-rule-engine/engine"
	"github.com/hyperjumptech/grule-rule-engine/pkg"
	"log"
)

// 规则帮助类
type RuleHelper struct {
	engine        *engine.GruleEngine
	knowledgeBase *ast.KnowledgeBase
	dataCtx       ast.IDataContext
}

func (rulehelper *RuleHelper) LoadRule(drls string) {

	knowledgeLibrary := ast.NewKnowledgeLibrary()
	ruleBuilder := builder.NewRuleBuilder(knowledgeLibrary)

	drls = `
rule CheckRegionNotChina "CheckRegionNotChina" salience 10 {
    when 
        fact.SRC_INFO.CONTENT_LENGTH == 0 && fact.SRC_INFO.HOST == "mybaidu1.com:8081"
    then
        fact.ExecResult = 1;
		Retract("CheckRegionNotChina");
}
`
	byteArr := pkg.NewBytesResource([]byte(drls))
	err := ruleBuilder.BuildRuleFromResource("Region", "0.0.1", byteArr)
	if err != nil {
		log.Fatal(err)
	}

	rulehelper.knowledgeBase = knowledgeLibrary.NewKnowledgeBaseInstance("Region", "0.0.1")

	rulehelper.engine = engine.NewGruleEngine()
}
func (rulehelper *RuleHelper) Exec(key string, ruleinfo *innerbean.WAF_REQUEST_FULL) error {

	//rulehelper.dataCtx = ast.NewDataContext()
	//rulehelper.dataCtx.Add(key, ruleinfo)
	dataCtx := ast.NewDataContext()
	dataCtx.Add(key, ruleinfo)
	err := rulehelper.engine.Execute(dataCtx, rulehelper.knowledgeBase)
	//err:= rulehelper.engine.Execute(rulehelper.dataCtx, rulehelper.knowledgeBase)
	if err != nil {
		log.Fatal(err)
	}
	return err
}
