package main

import (
	"SamWaf/global"
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
		case remoteConfig := <-global.GWAF_CHAN_RULE:
			//TODO 需要把删除的那部分数据从数据口里面去掉
			hostTarget[hostCode[remoteConfig[0].HostCode]].RuleData = remoteConfig
			hostTarget[hostCode[remoteConfig[0].HostCode]].Rule.LoadRules(remoteConfig)
			zlog.Debug("远程配置", zap.Any("remoteConfig", remoteConfig))
			break
		case remoteAntiCC := <-global.GWAF_CHAN_ANTICC:
			hostTarget[hostCode[remoteAntiCC.HostCode]].pluginIpRateLimiter = plugin.NewIPRateLimiter(rate.Limit(remoteAntiCC.Rate), remoteAntiCC.Limit)
			zlog.Debug("远程配置", zap.Any("remoteAntiCC", remoteAntiCC))
			break
		case remoteUrlWhite := <-global.GWAF_CHAN_UrlWhite:
			hostTarget[hostCode[remoteUrlWhite[0].HostCode]].UrlWhiteLists = remoteUrlWhite
			zlog.Debug("远程配置", zap.Any("UrlWhiteLists", remoteUrlWhite))
			break
		case remoteIpWhite := <-global.GWAF_CHAN_IpWhite:
			hostTarget[hostCode[remoteIpWhite[0].HostCode]].IPWhiteLists = remoteIpWhite
			zlog.Debug("远程配置", zap.Any("IPWhiteLists", remoteIpWhite))
			break
		case remoteLdpUrls := <-global.GWAF_CHAN_LdpUrl:
			hostTarget[hostCode[remoteLdpUrls[0].HostCode]].LdpUrlLists = remoteLdpUrls
			zlog.Debug("远程配置", zap.Any("LdpUrlLists", remoteLdpUrls))
			break
		case remoteUrlBlock := <-global.GWAF_CHAN_UrlBlock:
			hostTarget[hostCode[remoteUrlBlock[0].HostCode]].UrlBlockLists = remoteUrlBlock
			zlog.Debug("远程配置", zap.Any("UrlBlockLists", remoteUrlBlock))
			break
		case remoteIpBlock := <-global.GWAF_CHAN_IpBlock:
			hostTarget[hostCode[remoteIpBlock[0].HostCode]].IPBlockLists = remoteIpBlock
			zlog.Debug("远程配置", zap.Any("IPBlockLists", remoteIpBlock))
			break
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
