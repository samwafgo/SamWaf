package main

import (
	"SamWaf/global"
	"SamWaf/model"
	"log"
	"net/http"
	"strconv"
	"time"
)

func main() {

	/*runtime.GOMAXPROCS(1) // 限制 CPU 使用数，避免过载
	runtime.SetMutexProfileFraction(1) // 开启对锁调用的跟踪
	runtime.SetBlockProfileRate(1) // 开启对阻塞操作的跟踪
	go func() {

		err2:=http.ListenAndServe("0.0.0.0:16060", nil)
		time.Sleep(10000)
		log.Fatal(err2)
	}()
	*/

	//初始化本地数据库
	InitDb()

	//启动waf
	phttphandler = &baseHandle{}
	http.Handle("/", phttphandler)
	Start_WAF()

	//启动管理界面
	go func() {
		StartLocalServer()
	}()

	//定时取规则并更新
	go func() {

		for {
			for code, host := range hostCode {
				if engineCurrentStatus == 0 {
					log.Println("引擎已关闭，放弃提取规则")
					continue
				}
				var vcnt int
				global.GWAF_LOCAL_DB.Debug().Model(&model.Rules{}).Where("host_code = ? and user_code=? ",
					code, global.GWAF_USER_CODE).Select("sum(rule_version) as vcnt").Row().Scan(&vcnt)
				log.Println("主机host" + code + " 版本" + strconv.Itoa(vcnt))
				var ruleconfig []model.Rules
				if vcnt > 0 {
					global.GWAF_LOCAL_DB.Debug().Where("host_code = ? and user_code=?  ", code, global.GWAF_USER_CODE).Find(&ruleconfig)
					if vcnt > hostTarget[host].RuleVersionSum {
						log.Println("主机host" + code + " 有最新规则")
						hostTarget[host].RuleVersionSum = vcnt
						//说明该code有更新
						hostRuleChan <- ruleconfig

					} else {
						log.Println("主机host" + code + " 有最新规则")
					}
				}

			}
			time.Sleep(10 * time.Second) // 10s重新读取一次

		}

	}()
	for {
		select {
		case remoteConfig := <-hostRuleChan:
			//TODO 需要把删除的那部分数据从数据口里面去掉
			hostTarget[hostCode[remoteConfig[0].HostCode]].RuleData = remoteConfig
			hostTarget[hostCode[remoteConfig[0].HostCode]].Rule.LoadRules(remoteConfig)
			log.Println(remoteConfig)
			break

		case engineStatus := <-engineChan:
			if engineStatus == 1 {
				log.Println("准备关闭WAF引擎")
				CLoseWAF()
				log.Println("准备启动WAF引擎")
				Start_WAF()

			}
			break
		}

	}
}
