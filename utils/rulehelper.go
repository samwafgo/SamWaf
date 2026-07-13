package utils

import (
	"SamWaf/common/zlog"
	"SamWaf/innerbean"
	"SamWaf/model"
	"errors"
	"fmt"
	"regexp"

	"github.com/hyperjumptech/grule-rule-engine/ast"
	"github.com/hyperjumptech/grule-rule-engine/builder"
	"github.com/hyperjumptech/grule-rule-engine/engine"
	"github.com/hyperjumptech/grule-rule-engine/pkg"
)

// 规则帮助类
type RuleHelper struct {
	engine           *engine.GruleEngine
	KnowledgeBase    *ast.KnowledgeBase
	knowledgeLibrary *ast.KnowledgeLibrary
	ruleBuilder      *builder.RuleBuilder
	// 规则动作表 key为规则名(含R前缀，与 ast.RuleEntry.RuleName 一致)
	// 只在规则加载阶段写入，加载完成后只读；规则变更走 copy-on-write 整体换掉 RuleHelper，因此无需加锁
	ruleActions map[string]RuleActionInfo
}

func (rulehelper *RuleHelper) InitRuleEngine() {
	rulehelper.knowledgeLibrary = ast.NewKnowledgeLibrary()
	rulehelper.ruleBuilder = builder.NewRuleBuilder(rulehelper.knowledgeLibrary)
	rulehelper.engine = engine.NewGruleEngine()
	rulehelper.ruleActions = make(map[string]RuleActionInfo)
}

// GetRuleAction 获取规则的动作，没有声明动作的规则默认为拦截
func (rulehelper *RuleHelper) GetRuleAction(ruleName string) RuleActionInfo {
	if rulehelper.ruleActions != nil {
		if info, ok := rulehelper.ruleActions[ruleName]; ok && info.Action != "" {
			return info
		}
	}
	return RuleActionInfo{Action: RuleActionDeny}
}

// mergeRuleActions 把规则文本里解析出的动作并入动作表
func (rulehelper *RuleHelper) mergeRuleActions(ruleContent string) {
	if rulehelper.ruleActions == nil {
		rulehelper.ruleActions = make(map[string]RuleActionInfo)
	}
	for name, info := range ExtractRuleActions(ruleContent) {
		rulehelper.ruleActions[name] = info
	}
}

func (rulehelper *RuleHelper) LoadRuleString(ruleContent string) error {

	rulehelper.ruleActions = make(map[string]RuleActionInfo)
	byteArr := pkg.NewBytesResource([]byte(ruleContent))
	err := rulehelper.ruleBuilder.BuildRuleFromResource("Region", "0.0.1", byteArr)
	if err != nil {
		zlog.Error("LoadRule", err)
	}
	rulehelper.mergeRuleActions(ruleContent)
	rulehelper.KnowledgeBase, err = rulehelper.knowledgeLibrary.NewKnowledgeBaseInstance("Region", "0.0.1")
	return err
}
func (rulehelper *RuleHelper) LoadRule(ruleconfig model.Rules) error {

	rulehelper.ruleActions = make(map[string]RuleActionInfo)
	byteArr := pkg.NewBytesResource([]byte(ruleconfig.RuleContent))
	err := rulehelper.ruleBuilder.BuildRuleFromResource("Region", "0.0.1", byteArr)
	if err != nil {
		zlog.Error("LoadRule", err)
	}
	rulehelper.mergeRuleActions(ruleconfig.RuleContent)
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
	rulehelper.ruleActions = make(map[string]RuleActionInfo)

	//先建一个空的资源，保证即使一条规则都没有(或全部编译失败)，KnowledgeBase 依然存在
	if err := rulehelper.ruleBuilder.BuildRuleFromResource("Region", "0.0.1", pkg.NewBytesResource([]byte(""))); err != nil {
		zlog.Error("LoadRules 初始化规则库失败", err)
	}

	rulestr := ""
	//逐条编译：单条规则语法有问题只跳过这一条，不能把整个网站的规则都带崩（否则等于防护被清零）
	for _, v := range ruleconfig {
		if v.RuleStatus != 1 {
			continue
		}
		byteArr := pkg.NewBytesResource([]byte(v.RuleContent))
		if err := rulehelper.ruleBuilder.BuildRuleFromResource("Region", "0.0.1", byteArr); err != nil {
			//不打印规则内容，规则里可能带着攻击载荷或敏感值
			zlog.Error("LoadRules 规则编译失败，已跳过该条规则", "ruleCode", v.RuleCode, "ruleName", v.RuleName, "err", err.Error())
			continue
		}
		rulehelper.mergeRuleActions(v.RuleContent)
		rulestr = rulestr + v.RuleContent + " \n"
	}

	knowledgeBase, err := rulehelper.knowledgeLibrary.NewKnowledgeBaseInstance("Region", "0.0.1")
	if err != nil {
		zlog.Error("LoadRules", err)
	}
	rulehelper.KnowledgeBase = knowledgeBase

	return rulestr, err
}
func (rulehelper *RuleHelper) Exec(key string, ruleinfo *innerbean.WAF_REQUEST_FULL) error {
	dataCtx := ast.NewDataContext()
	dataCtx.Add(key, ruleinfo)
	dataCtx.Add("RF", innerbean.NewRuleFunc()) // 注册规则函数助手
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
	dataCtx.Add("RF", innerbean.NewRuleFunc()) // 注册规则函数助手
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
	err = dataCtx.Add("RF", innerbean.NewRuleFunc()) // 注册规则函数助手
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
