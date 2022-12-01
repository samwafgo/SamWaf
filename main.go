package main

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/plugin"
	"SamWaf/utils/zlog"
	dlp "github.com/bytedance/godlp"
	"github.com/go-co-op/gocron"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
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

	//定时取规则并更新（考虑后期定时拉取公共规则 待定，可能会影响实际生产）

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
		case msg := <-global.GWAF_CHAN_MSG:
			switch msg.Type {
			case enums.ChanTypeWhiteIP:
				hostTarget[hostCode[msg.HostCode]].IPWhiteLists = msg.Content.([]model.IPWhiteList)
				zlog.Debug("远程配置", zap.Any("IPWhiteLists", msg.Content.([]model.IPWhiteList)))
				break
			case enums.ChanTypeWhiteURL:
				hostTarget[hostCode[msg.HostCode]].UrlWhiteLists = msg.Content.([]model.URLWhiteList)
				zlog.Debug("远程配置", zap.Any("UrlWhiteLists", msg.Content.([]model.URLWhiteList)))
				break
			case enums.ChanTypeBlockIP:
				hostTarget[hostCode[msg.HostCode]].IPBlockLists = msg.Content.([]model.IPBlockList)
				zlog.Debug("远程配置", zap.Any("IPBlockLists", msg))
				break
			case enums.ChanTypeBlockURL:
				hostTarget[hostCode[msg.HostCode]].UrlBlockLists = msg.Content.([]model.URLBlockList)
				zlog.Debug("远程配置", zap.Any("UrlBlockLists", msg.Content.([]model.URLBlockList)))
				break
			case enums.ChanTypeLdp:
				hostTarget[hostCode[msg.HostCode]].LdpUrlLists = msg.Content.([]model.LDPUrl)
				zlog.Debug("远程配置", zap.Any("LdpUrlLists", msg.Content.([]model.LDPUrl)))
				break
			case enums.ChanTypeRule:
				hostTarget[hostCode[msg.HostCode]].RuleData = msg.Content.([]model.Rules)
				hostTarget[hostCode[msg.HostCode]].Rule.LoadRules(msg.Content.([]model.Rules))
				zlog.Debug("远程配置", zap.Any("Rule", msg.Content.([]model.Rules)))
				break
			case enums.ChanTypeAnticc:
				hostTarget[hostCode[msg.HostCode]].pluginIpRateLimiter = plugin.NewIPRateLimiter(rate.Limit(msg.Content.(model.AntiCC).Rate), msg.Content.(model.AntiCC).Limit)
				zlog.Debug("远程配置", zap.Any("Anticc", msg.Content.(model.AntiCC)))
				break

			case enums.ChanTypeHost: //此处待定
				break
			} //end switch
		case engineStatus := <-global.GWAF_CHAN_ENGINE:
			if engineStatus == 1 {
				zlog.Info("准备关闭WAF引擎")
				CLoseWAF()
				zlog.Info("准备启动WAF引擎")
				Start_WAF()

			}
			break
		case host := <-global.GWAF_CHAN_HOST:

			hostTarget[host.Host+":"+strconv.Itoa(host.Port)].Host.GUARD_STATUS = host.GUARD_STATUS
			zlog.Debug("规则", zap.Any("主机", host))
			break
		}

	}
}
