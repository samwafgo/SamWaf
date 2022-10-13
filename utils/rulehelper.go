package utils

import (
	"SamWaf/innerbean"
	"SamWaf/model"
	"github.com/hyperjumptech/grule-rule-engine/ast"
	"github.com/hyperjumptech/grule-rule-engine/builder"
	"github.com/hyperjumptech/grule-rule-engine/engine"
	"github.com/hyperjumptech/grule-rule-engine/pkg"
	"log"
)

// 规则帮助类
type RuleHelper struct {
	engine           *engine.GruleEngine
	knowledgeBase    *ast.KnowledgeBase
	knowledgeLibrary *ast.KnowledgeLibrary
	ruleBuilder      *builder.RuleBuilder
}

func (rulehelper *RuleHelper) LoadRule(ruleconfig model.Rules) {

	rulehelper.knowledgeLibrary = ast.NewKnowledgeLibrary()
	rulehelper.ruleBuilder = builder.NewRuleBuilder(rulehelper.knowledgeLibrary)
	byteArr := pkg.NewBytesResource([]byte(ruleconfig.RuleContent))
	err := rulehelper.ruleBuilder.BuildRuleFromResource("Region", "0.0.1", byteArr)
	if err != nil {
		log.Fatal(err)
	}

	rulehelper.knowledgeBase = rulehelper.knowledgeLibrary.NewKnowledgeBaseInstance("Region", "0.0.1")

	rulehelper.engine = engine.NewGruleEngine()
}

func (rulehelper *RuleHelper) LoadRules(ruleconfig []model.Rules) string {

	rulehelper.knowledgeLibrary = ast.NewKnowledgeLibrary()
	rulehelper.ruleBuilder = builder.NewRuleBuilder(rulehelper.knowledgeLibrary)

	//rulehelper.dataCtx = ast.NewDataContext()
	/*drls = `
	rule CheckRegionNotChina "CheckRegionNotChina" salience 10 {
	    when
	        fact.SRC_INFO.CONTENT_LENGTH == 0 && fact.SRC_INFO.HOST == "mybaidu1.com:8081"
	    then
	        fact.ExecResult = 1;
			Retract("CheckRegionNotChina");
	}
	`*/
	rulestr := ""
	for _, v := range ruleconfig {
		rulestr = rulestr + v.RuleContent + " \n"
	}
	byteArr := pkg.NewBytesResource([]byte(rulestr))
	err := rulehelper.ruleBuilder.BuildRuleFromResource("Region", "0.0.1", byteArr)
	if err != nil {
		log.Fatal(err)
	}

	rulehelper.knowledgeBase = rulehelper.knowledgeLibrary.NewKnowledgeBaseInstance("Region", "0.0.1")

	rulehelper.engine = engine.NewGruleEngine()
	return rulestr
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

func (rulehelper *RuleHelper) Match(key string, ruleinfo *innerbean.WebLog) ([]*ast.RuleEntry, error) {

	defer func() {
		e := recover()
		if e != nil { // 捕获该协程的panic 111111
			log.Println("Match error ", e)
		}
	}()
	dataCtx := ast.NewDataContext()
	dataCtx.Add(key, ruleinfo)
	return rulehelper.engine.FetchMatchingRules(dataCtx, rulehelper.knowledgeBase)
}
