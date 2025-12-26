package utils

import (
	"SamWaf/common/zlog"
	"SamWaf/innerbean"
	"SamWaf/model"
	"errors"
	"fmt"
	"github.com/hyperjumptech/grule-rule-engine/ast"
	"github.com/hyperjumptech/grule-rule-engine/builder"
	"github.com/hyperjumptech/grule-rule-engine/engine"
	"github.com/hyperjumptech/grule-rule-engine/pkg"
	"regexp"
)

// 规则帮助类
type RuleHelper struct {
	engine           *engine.GruleEngine
	KnowledgeBase    *ast.KnowledgeBase
	knowledgeLibrary *ast.KnowledgeLibrary
	ruleBuilder      *builder.RuleBuilder
}

func (rulehelper *RuleHelper) InitRuleEngine() {
	rulehelper.knowledgeLibrary = ast.NewKnowledgeLibrary()
	rulehelper.ruleBuilder = builder.NewRuleBuilder(rulehelper.knowledgeLibrary)
	rulehelper.engine = engine.NewGruleEngine()
}
func (rulehelper *RuleHelper) LoadRuleString(ruleContent string) error {

	byteArr := pkg.NewBytesResource([]byte(ruleContent))
	err := rulehelper.ruleBuilder.BuildRuleFromResource("Region", "0.0.1", byteArr)
	if err != nil {
		zlog.Error("LoadRule", err)
	}
	rulehelper.KnowledgeBase, err = rulehelper.knowledgeLibrary.NewKnowledgeBaseInstance("Region", "0.0.1")
	return err
}
func (rulehelper *RuleHelper) LoadRule(ruleconfig model.Rules) error {

	byteArr := pkg.NewBytesResource([]byte(ruleconfig.RuleContent))
	err := rulehelper.ruleBuilder.BuildRuleFromResource("Region", "0.0.1", byteArr)
	if err != nil {
		zlog.Error("LoadRule", err)
	}
	rulehelper.KnowledgeBase, err = rulehelper.knowledgeLibrary.NewKnowledgeBaseInstance("Region", "0.0.1")
	return err
}

func (rulehelper *RuleHelper) LoadRules(ruleconfig []model.Rules) (string, error) {

	defer func() {
		e := recover()
		if e != nil { // 捕获该协程的panic 111111
			zlog.Error("LoadRules error ", e)
		}
	}()
	//清除之前的规则
	for _, value := range rulehelper.knowledgeLibrary.Library {
		for ruleKey, _ := range value.RuleEntries {
			rulehelper.knowledgeLibrary.RemoveRuleEntry(ruleKey, value.Name, value.Version)
		}
	}
	rulestr := ""
	for _, v := range ruleconfig {
		if v.RuleStatus == 1 {
			rulestr = rulestr + v.RuleContent + " \n"
		}
	}
	byteArr := pkg.NewBytesResource([]byte(rulestr))
	err := rulehelper.ruleBuilder.BuildRuleFromResource("Region", "0.0.1", byteArr)
	if err != nil {
		zlog.Error("LoadRules", err)
	}

	rulehelper.KnowledgeBase, err = rulehelper.knowledgeLibrary.NewKnowledgeBaseInstance("Region", "0.0.1")

	return rulestr, err
}
func (rulehelper *RuleHelper) Exec(key string, ruleinfo *innerbean.WAF_REQUEST_FULL) error {
	dataCtx := ast.NewDataContext()
	dataCtx.Add(key, ruleinfo)
	err := rulehelper.engine.Execute(dataCtx, rulehelper.KnowledgeBase)
	if err != nil {
		zlog.Error("Exec", err)
	}
	return err
}

func (rulehelper *RuleHelper) Match(key string, ruleinfo *innerbean.WebLog) ([]*ast.RuleEntry, error) {

	defer func() {
		e := recover()
		if e != nil { // 捕获该协程的panic 111111
			zlog.Warn("RuleMatch", e)
		}
	}()
	dataCtx := ast.NewDataContext()
	dataCtx.Add(key, ruleinfo)
	if rulehelper.KnowledgeBase == nil {
		return nil, errors.New("没有规则数据")
	}
	return rulehelper.engine.FetchMatchingRules(dataCtx, rulehelper.KnowledgeBase)
}
func (rulehelper *RuleHelper) CheckRuleAvailable(ruleText string) error {
	myFact := &innerbean.WebLog{
		SRC_IP: "127.0.0.1",
	}
	dataCtx := ast.NewDataContext()
	err := dataCtx.Add("MF", myFact)
	if err != nil {
		return err
	}
	knowledgeLibrary := ast.NewKnowledgeLibrary()
	ruleBuilder := builder.NewRuleBuilder(knowledgeLibrary)

	byteArr := pkg.NewBytesResource([]byte(ruleText))
	err = ruleBuilder.BuildRuleFromResource("CheckRule", "0.0.1", byteArr)
	if err != nil {
		return err
	}

	knowledgeBase, err := knowledgeLibrary.NewKnowledgeBaseInstance("CheckRule", "0.0.1")
	if err != nil {
		return err
	}
	myEngine := engine.NewGruleEngine()
	processType := "match"
	if processType == "match" {
		_, err := myEngine.FetchMatchingRules(dataCtx, knowledgeBase)
		if err != nil {
			return err
		}
	}
	return nil
}

// ExtractRuleName 提取规则名称
func (rulehelper *RuleHelper) ExtractRuleName(ruleText string) (string, error) {
	// 定义正则表达式
	re := regexp.MustCompile(`rule\s+R([^"\s]+)`)

	// 查找匹配项
	matches := re.FindStringSubmatch(ruleText)
	if len(matches) < 2 {
		return "", fmt.Errorf("未找到匹配的 rule 名称")
	}

	return matches[1], nil
}
