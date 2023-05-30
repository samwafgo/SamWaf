package main

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/plugin"
	"SamWaf/utils"
	"SamWaf/utils/zlog"
	"SamWaf/wafenginecore"
	"SamWaf/waftask"
	"SamWaf/xdaemon"
	"crypto/tls"
	dlp "github.com/bytedance/godlp"
	"github.com/go-co-op/gocron"
	Wssocket "github.com/gorilla/websocket"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
	"time"
)

func main() {

	rversion := "初始化系统 版本号：" + global.GWAF_RELEASE_VERSION_NAME + "(" + global.GWAF_RELEASE_VERSION + ")"
	if global.GWAF_RELEASE == "false" {
		rversion = rversion + " 调试版本"
	} else {
		rversion = rversion + " 发行版本"
	}
	if runtime.GOOS == "linux" {
		rversion = rversion + " linux"
	} else if runtime.GOOS == "windows" {
		rversion = rversion + " windows"
	}

	zlog.Info(rversion)

	global.GWAF_LAST_UPDATE_TIME = time.Now()

	pwd, err := os.Getwd()
	syscall.Setenv("ZONEINFO", pwd+"//data//zoneinfo")
	if err != nil {
		log.Fatal(err)
	}
	// if received any kind of command, do it
	if len(os.Args) > 1 {
		command := os.Args[1]
		switch command {
		case "-d":
			logFile := "./logs/daemon.log"
			//启动一个子进程后主程序退出
			xdaemon.Background(logFile, true)
			break
		case "-c":
			println("关闭")
			if runtime.GOOS == "windows" {
				c := exec.Command("taskkill.exe", "/f", "/im", "SamWaf.exe")
				c.Start()
			} else {
				println("SamWaf -d")
			}
			break
		case "-help":
			if runtime.GOOS == "windows" {
				println("SamWaf.exe  -d 是后台运行 -c 是强制关闭  -help 是帮助说明")
			} else {
				println("SamWaf -d 是后台运行 -c 是强制关闭  -help 是帮助说明")
			}
			break
		default:
			println(command)
		}
	}

	//守护程序开始
	//xdaemon.DaemonProcess("GoTest.exe","./logs/damon.log")

	if global.GWAF_RELEASE == "false" {
		/*runtime.GOMAXPROCS(1)              // 限制 CPU 使用数，避免过载
		runtime.SetMutexProfileFraction(1) // 开启对锁调用的跟踪
		runtime.SetBlockProfileRate(1)     // 开启对阻塞操作的跟踪*/
		go func() {

			err2 := http.ListenAndServe("0.0.0.0:16060", nil)
			zlog.Error("调试报错", err2)
		}()
	}

	//初始化本地数据库
	wafenginecore.InitDb()

	//初始化队列引擎
	wafenginecore.InitDequeEngine()
	//启动队列消费
	go func() {
		wafenginecore.ProcessDequeEngine()
	}()

	//启动waf
	wafEngine := wafenginecore.WafEngine{
		HostTarget: map[string]*wafenginmodel.HostSafe{},
		//主机和code的关系
		HostCode:     map[string]string{},
		ServerOnline: map[int]innerbean.ServerRunTime{},
		//所有证书情况 对应端口 可能多个端口都是https 443，或者其他非标准端口也要实现https证书
		AllCertificate: map[int]map[string]*tls.Certificate{},
		EsHelper:       utils.EsHelper{},

		EngineCurrentStatus: 0, // 当前waf引擎状态
	}
	http.Handle("/", &wafEngine)
	wafEngine.Start_WAF()

	//启动管理界面
	go func() {
		wafenginecore.StartLocalServer()
	}()

	//启动websocket
	global.GWebSocket = map[string]*Wssocket.Conn{}
	//定时取规则并更新（考虑后期定时拉取公共规则 待定，可能会影响实际生产）

	//定时器 （后期考虑是否独立包处理）
	timezone, _ := time.LoadLocation("Asia/Shanghai")
	s := gocron.NewScheduler(timezone)

	// 每10秒执行一次
	s.Every(10).Seconds().Do(func() {
		zlog.Debug("i am alive")
		go waftask.TaskCounter()
	})

	// 获取最近token
	s.Every(1).Hour().Do(func() {
		//defer func() {
		//	 zlog.Info("token errr")
		//}()
		zlog.Debug("获取最新token")
		go waftask.TaskWechatAccessToken()

	})
	// 每天早晚8点进行数据汇总通知
	s.Every(1).Day().At("08:00;20:00").Do(func() {
		go waftask.TaskStatusNotify()
	})

	// 每天早5点删除历史信息
	s.Every(1).Day().At("05:00").Do(func() {
		go waftask.TaskDeleteHistoryInfo()
	})
	s.StartAsync()

	//脱敏处理初始化
	global.GWAF_DLP, _ = dlp.NewEngine("wafDlp")
	global.GWAF_DLP.ApplyConfigDefault()
	for {
		select {
		case msg := <-global.GWAF_CHAN_MSG:
			if wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]] != nil && wafEngine.HostCode[msg.HostCode] != "" {
				switch msg.Type {
				case enums.ChanTypeWhiteIP:
					wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]].IPWhiteLists = msg.Content.([]model.IPWhiteList)
					zlog.Debug("远程配置", zap.Any("IPWhiteLists", msg.Content.([]model.IPWhiteList)))
					break
				case enums.ChanTypeWhiteURL:
					wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]].UrlWhiteLists = msg.Content.([]model.URLWhiteList)
					zlog.Debug("远程配置", zap.Any("UrlWhiteLists", msg.Content.([]model.URLWhiteList)))
					break
				case enums.ChanTypeBlockIP:
					wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]].IPBlockLists = msg.Content.([]model.IPBlockList)
					zlog.Debug("远程配置", zap.Any("IPBlockLists", msg))
					break
				case enums.ChanTypeBlockURL:
					wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]].UrlBlockLists = msg.Content.([]model.URLBlockList)
					zlog.Debug("远程配置", zap.Any("UrlBlockLists", msg.Content.([]model.URLBlockList)))
					break
				case enums.ChanTypeLdp:
					wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]].LdpUrlLists = msg.Content.([]model.LDPUrl)
					zlog.Debug("远程配置", zap.Any("LdpUrlLists", msg.Content.([]model.LDPUrl)))
					break
				case enums.ChanTypeRule:
					wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]].RuleData = msg.Content.([]model.Rules)
					wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]].Rule.LoadRules(msg.Content.([]model.Rules))
					zlog.Debug("远程配置", zap.Any("Rule", msg.Content.([]model.Rules)))
					break
				case enums.ChanTypeAnticc:
					wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]].PluginIpRateLimiter = plugin.NewIPRateLimiter(rate.Limit(msg.Content.(model.AntiCC).Rate), msg.Content.(model.AntiCC).Limit)
					zlog.Debug("远程配置", zap.Any("Anticc", msg.Content.(model.AntiCC)))
					break

				case enums.ChanTypeHost: //此处待定
					break
				} //end switch
			}
			break
		case engineStatus := <-global.GWAF_CHAN_ENGINE:
			if engineStatus == 1 {
				zlog.Info("准备关闭WAF引擎")
				wafEngine.CLoseWAF()
				zlog.Info("准备启动WAF引擎")
				wafEngine.Start_WAF()

			}
			break
		case host := <-global.GWAF_CHAN_HOST:

			wafEngine.HostTarget[host.Host+":"+strconv.Itoa(host.Port)].Host.GUARD_STATUS = host.GUARD_STATUS
			zlog.Debug("规则", zap.Any("主机", host))
			break
		}

	}
	zlog.Info("normal program close")
}
