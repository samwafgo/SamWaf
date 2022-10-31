package main

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/utils/zlog"
	dlp "github.com/bytedance/godlp"
	"github.com/go-co-op/gocron"
	"go.uber.org/zap"
	"net/http"
	"strconv"
	"time"
)

func main() {
	zlog.Info("初始化系统")
	if !global.GWAF_RELEASE {
		zlog.Info("调试版本")
	}
	global.GWAF_LAST_UPDATE_TIME = time.Now()

	/*runtime.GOMAXPROCS(1)              // 限制 CPU 使用数，避免过载
	runtime.SetMutexProfileFraction(1) // 开启对锁调用的跟踪
	runtime.SetBlockProfileRate(1)     // 开启对阻塞操作的跟踪
	go func() {

		err2 := http.ListenAndServe("0.0.0.0:16060", nil)
		time.Sleep(10000)
		log.Fatal(err2)
	}()*/

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
					zlog.Info("引擎已关闭，放弃提取规则")
					continue
				}
				var vcnt int
				global.GWAF_LOCAL_DB.Debug().Model(&model.Rules{}).Where("host_code = ? and user_code=? ",
					code, global.GWAF_USER_CODE).Select("sum(rule_version) as vcnt").Row().Scan(&vcnt)
				zlog.Debug("主机host" + code + " 版本" + strconv.Itoa(vcnt))
				var ruleconfig []model.Rules
				if vcnt > 0 {
					global.GWAF_LOCAL_DB.Debug().Where("host_code = ? and user_code=?  ", code, global.GWAF_USER_CODE).Find(&ruleconfig)
					if vcnt > hostTarget[host].RuleVersionSum {
						zlog.Debug("主机host" + code + " 有最新规则")
						hostTarget[host].RuleVersionSum = vcnt
						//说明该code有更新
						hostRuleChan <- ruleconfig

					}
				}

			}
			time.Sleep(10 * time.Second) // 10s重新读取一次

		}

	}()

	//定时器
	timezone, _ := time.LoadLocation("Asia/Shanghai")
	s := gocron.NewScheduler(timezone)

	// 每秒执行一次 TODO 改数据成分钟统计
	s.Every(10).Seconds().Do(func() {
		zlog.Debug("i am alive")
		go TaskCounter()
	})
	s.StartAsync()

	//脱敏处理初始化
	global.GWAF_DLP, _ = dlp.NewEngine("wafDlp")
	global.GWAF_DLP.ApplyConfigDefault()
	for {
		select {
		case remoteConfig := <-hostRuleChan:
			//TODO 需要把删除的那部分数据从数据口里面去掉
			hostTarget[hostCode[remoteConfig[0].HostCode]].RuleData = remoteConfig
			hostTarget[hostCode[remoteConfig[0].HostCode]].Rule.LoadRules(remoteConfig)
			zlog.Debug("远程配置", zap.Any("remoteConfig", remoteConfig))
			break

		case engineStatus := <-engineChan:
			if engineStatus == 1 {
				zlog.Info("准备关闭WAF引擎")
				CLoseWAF()
				zlog.Info("准备启动WAF引擎")
				Start_WAF()

			}
			break
		case host := <-hostChan:

			hostTarget[host.Host+":"+strconv.Itoa(host.Port)].Host.GUARD_STATUS = host.GUARD_STATUS
			zlog.Debug("规则", zap.Any("主机", host))
			break
		}

	}
}
