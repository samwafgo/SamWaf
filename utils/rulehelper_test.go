package utils

import (
	"SamWaf/innerbean"
	"SamWaf/model"
	"fmt"
	"testing"
)

func TestRuleHelper_Match(t *testing.T) {
	//加载主机对于的规则
	ruleHelper := &RuleHelper{}
	ruleHelper.InitRuleEngine()

	drls := `
	
rule R1ca0bf1c409e4c1b823c995afe7733b0 "禁止一些robotahrefs" salience 10 {
    when 
        MF.USER_AGENT.Contains("amazonbot") == True ||  MF.USER_AGENT.Contains("1212") == True ||  MF.USER_AGENT.Contains("Mozilla") == True
    then
        
		Retract("R1ca0bf1c409e4c1b823c995afe7733b0");
} `
	var ruleconfigs []model.Rules
	rule := model.Rules{
		HostCode:        "",
		RuleCode:        "",
		RuleName:        "",
		RuleContent:     drls,
		RuleContentJSON: "",
		RuleVersionName: "",
		RuleVersion:     0,
		IsPublicRule:    0,
		IsManualRule:    0,
		RuleStatus:      0,
	}
	ruleconfigs = append(ruleconfigs, rule)
	ruleHelper.LoadRules(ruleconfigs)

	//weblog
	logs := innerbean.WebLog{
		USER_AGENT: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/600.2.5 (KHTML, like Gecko) Version/8.0.2 Safari/600.2.5 (Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot)",
	}
	ruleMatchs, err := ruleHelper.Match("MF", &logs)
	if err == nil {
		if len(ruleMatchs) > 0 {
			rulestr := ""
			for _, v := range ruleMatchs {
				rulestr = rulestr + v.RuleDescription + ","
			}
			fmt.Printf("%s", rulestr)
			return
		}
	}

}
