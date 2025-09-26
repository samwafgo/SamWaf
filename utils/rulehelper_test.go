package utils

import (
	"SamWaf/innerbean"
	"SamWaf/model"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
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

// TestWebLog_GetHeaderValue 测试WebLog的GetHeaderValue方法
func TestWebLog_GetHeaderValue(t *testing.T) {
	//加载主机对于的规则
	ruleHelper := &RuleHelper{}
	ruleHelper.InitRuleEngine()

	drls := `
	
rule R1ca0bf1c409e4c1b823c995afe7733b0 "判断header里面的组合信息" salience 10 {
    when 
        MF.GetHeaderValue("Accept").Contains("text/plain") == True &&  MF.GetHeaderValue("X-Real-IP").Contains("10.0.0.1") == True 
    then
        
		Retract("R1ca0bf1c409e4c1b823c995afe7733b0");
} `
	var ruleconfigs []model.Rules
	rule := model.Rules{
		HostCode:        "",
		RuleCode:        "",
		RuleName:        "我是规则",
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
		HEADER: "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\r\n" +
			"Accept: application/json, text/plain, */*\r\n" +
			"Accept-Language: zh-CN,zh;q=0.9,en;q=0.8\r\n" +
			"Accept-Encoding: gzip, deflate, br\r\n" +
			"Content-Type: application/json\r\n" +
			"Content-Length: 123\r\n" +
			"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\r\n" +
			"X-Forwarded-For: 10.0.0.1, 192.168.1.1\r\n" +
			"X-Real-IP: 10.0.0.1\r\n" +
			"X-Custom-Header: custom-value-123\r\n" +
			"Cookie: session_id=abc123; user_pref=dark_mode\r\n" +
			"Referer: https://example.com/login\r\n" +
			"Origin: https://example.com\r\n" +
			"Connection: keep-alive\r\n" +
			"Cache-Control: no-cache\r\n",
	}
	ruleMatchs, err := ruleHelper.Match("MF", &logs)
	if err == nil {
		if len(ruleMatchs) > 0 {
			fmt.Printf("header里面的组合信息匹配成功，规则描述：%s\n", ruleMatchs[0].RuleDescription)
			rulestr := ""
			for _, v := range ruleMatchs {
				rulestr = rulestr + v.RuleDescription + ","
			}
			fmt.Printf("%s", rulestr)
			return
		} else {
			fmt.Printf("header里面的组合信息匹配失败\n")
		}
	}
}

// TestAllRulesInDirectory 测试rule_tests目录下所有规则文件
func TestAllRulesInDirectory(t *testing.T) {
	// 初始化规则引擎
	ruleHelper := &RuleHelper{}
	ruleHelper.InitRuleEngine()

	// 规则文件目录
	rulesDir := "c:\\huawei\\goproject\\SamWaf\\utils\\rule_tests"

	// 读取目录下所有文件
	files, err := ioutil.ReadDir(rulesDir)
	if err != nil {
		t.Fatalf("无法读取规则目录: %v", err)
	}

	// 遍历每个文件
	for _, file := range files {
		if file.IsDir() {
			continue // 跳过子目录
		}

		// 读取规则文件内容
		filePath := filepath.Join(rulesDir, file.Name())
		ruleContent, err := os.ReadFile(filePath)
		if err != nil {
			t.Errorf("无法读取规则文件 %s: %v", file.Name(), err)
			continue
		}

		// 测试单个规则文件
		t.Run(file.Name(), func(t *testing.T) {
			testSingleRuleFile(t, ruleHelper, file.Name(), string(ruleContent))
		})
	}
}

// testSingleRuleFile 测试单个规则文件
func testSingleRuleFile(t *testing.T, ruleHelper *RuleHelper, fileName string, ruleContent string) {
	// 创建规则配置
	var ruleconfigs []model.Rules
	rule := model.Rules{
		HostCode:        "",
		RuleCode:        strings.TrimSuffix(fileName, filepath.Ext(fileName)),
		RuleName:        strings.TrimSuffix(fileName, filepath.Ext(fileName)),
		RuleContent:     ruleContent,
		RuleContentJSON: "",
		RuleVersionName: "1.0",
		RuleVersion:     1,
		IsPublicRule:    0,
		IsManualRule:    1,
		RuleStatus:      1,
	}
	ruleconfigs = append(ruleconfigs, rule)

	// 加载规则
	_, err := ruleHelper.LoadRules(ruleconfigs)
	if err != nil {
		t.Errorf("加载规则文件 %s 失败: %v", fileName, err)
		return
	}

	// 创建测试用的WebLog对象
	webLog := &innerbean.WebLog{
		SRC_IP:     "192.168.1.1",
		URL:        "/admin/admin.php",
		USER_AGENT: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		REFERER:    "https://example.com",
		COOKIES:    "session=123456",
		HOST:       "example.com",
		METHOD:     "GET",
		COUNTRY:    "中国",
	}

	// 尝试匹配规则
	ruleMatches, err := ruleHelper.Match("MF", webLog)
	if err != nil {
		t.Errorf("规则匹配过程中出错 %s: %v", fileName, err)
		return
	}

	// 输出匹配结果
	t.Logf("规则文件 %s 测试结果:", fileName)
	if len(ruleMatches) > 0 {
		t.Logf("  - 匹配到 %d 条规则", len(ruleMatches))
		for i, match := range ruleMatches {
			t.Logf("  - 匹配 #%d: %s (%s)", i+1, match.RuleName, match.RuleDescription)
		}
	} else {
		t.Logf("  - 没有匹配到规则")
	}

	// 规则能被加载和执行即视为测试通过
	t.Logf("规则文件 %s 测试通过", fileName)
}
