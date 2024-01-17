package main

import (
	"SamWaf/cache"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/plugin"
	"SamWaf/utils"
	"SamWaf/utils/zlog"
	"SamWaf/wafdb"
	"SamWaf/wafenginecore"
	"SamWaf/wafsafeclear"
	"SamWaf/wafsnowflake"
	"SamWaf/waftask"
	"crypto/tls"
	"fmt"
	dlp "github.com/bytedance/godlp"
	"github.com/go-co-op/gocron"
	"github.com/kardianos/service"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
	"gorm.io/gorm"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"
)

// wafSystenService 实现了 service.Service 接口
type wafSystenService struct{}

// Start 是服务启动时调用的方法
func (m *wafSystenService) Start(s service.Service) error {
	go m.run()
	return nil
}

// Stop 是服务停止时调用的方法
func (m *wafSystenService) Stop(s service.Service) error {
	wafsafeclear.SafeClear()
	return nil
}

// 守护协程
func NeverExit(name string, f func()) {
	defer func() {
		if v := recover(); v != nil { // 侦测到一个恐慌
			zlog.Info("协程%s崩溃了，准备重启一个", name)
			go NeverExit(name, f) // 重启一个同功能协程
		}
	}()
	f()
}

// run 是服务的主要逻辑
func (m *wafSystenService) run() {

	/*// 启动一个 goroutine 来处理信号
	go func() {
		// 创建一个通道来接收信号
		signalCh := make(chan os.Signal, 1)

		// 根据操作系统设置不同的信号监听
		if runtime.GOOS == "windows" {
			signal.Notify(signalCh,  syscall.SIGINT,os.Interrupt, syscall.SIGTERM,os.Kill)
		} else { // Linux 系统
			signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
		}
		for {
			select {
			case sig := <-signalCh:
				fmt.Println("接收到信号:", sig)
				wafsafeclear.SafeClear()
				// 在这里执行你的清理操作或退出应用程序的代码
				os.Exit(0)
			}
		}
	}()*/

	// 在这里编写你的服务逻辑代码
	fmt.Println("Service is running...")
	//初始化cache
	global.GCACHE_WAFCACHE = cache.InitWafCache()
	//初始化锁写不锁度
	global.GWAF_MEASURE_PROCESS_DEQUEENGINE = cache.InitWafOnlyLockWrite()
	// 创建 Snowflake 实例
	global.GWAF_SNOWFLAKE_GEN = wafsnowflake.NewSnowflake(1609459200000, 1, 1) // 设置epoch时间、机器ID和数据中心ID
	//提前初始化
	global.GDATA_CURRENT_LOG_DB_MAP = map[string]*gorm.DB{}
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

	syscall.Setenv("ZONEINFO", utils.GetCurrentDir()+"//data//zoneinfo")

	//守护程序开始
	//xdaemon.DaemonProcess("GoTest.exe","./logs/damon.log")

	if global.GWAF_RELEASE == "false" {
		global.GUPDATE_VERSION_URL = "http://127.0.0.1:81/"
		/*runtime.GOMAXPROCS(1)              // 限制 CPU 使用数，避免过载
		runtime.SetMutexProfileFraction(1) // 开启对锁调用的跟踪
		runtime.SetBlockProfileRate(1)     // 开启对阻塞操作的跟踪*/
		go func() {

			err2 := http.ListenAndServe("0.0.0.0:16060", nil)
			zlog.Error("调试报错", err2)
		}()
	}

	//初始化本地数据库
	wafdb.InitCoreDb("")
	wafdb.InitLogDb("")
	wafdb.InitStatsDb("")
	//初始化队列引擎
	wafenginecore.InitDequeEngine()
	//启动队列消费
	go NeverExit("ProcessDequeEngine", wafenginecore.ProcessDequeEngine)

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
	wafEngine.StartWaf()

	//启动管理界面
	go func() {
		wafenginecore.StartLocalServer()
	}()

	//启动websocket
	global.GWebSocket = model.InitWafWebSocket()
	//定时取规则并更新（考虑后期定时拉取公共规则 待定，可能会影响实际生产）

	//定时器 （后期考虑是否独立包处理）
	timezone, _ := time.LoadLocation("Asia/Shanghai")
	s := gocron.NewScheduler(timezone)

	global.GWAF_LAST_UPDATE_TIME = time.Now()
	// 每1秒执行qps清空
	s.Every(1).Seconds().Do(func() {
		// 清零计数器
		atomic.StoreUint64(&global.GWAF_RUNTIME_QPS, 0)
		atomic.StoreUint64(&global.GWAF_RUNTIME_LOG_PROCESS, 0)
	})
	go waftask.TaskShareDbInfo()
	// 执行分库操作 （每天凌晨3点进行数据归档操作）
	s.Every(1).Day().At("03:00").Do(func() {
		if global.GDATA_CURRENT_CHANGE == false {
			go waftask.TaskShareDbInfo()
		} else {
			zlog.Debug("执行分库操作没完成，调度任务PASS")
		}
	})

	// 每10秒执行一次
	s.Every(10).Seconds().Do(func() {
		if global.GWAF_SWITCH_TASK_COUNTER == false {
			go waftask.TaskCounter()
		} else {
			zlog.Debug("统计还没完成，调度任务PASS")
		}
	})
	// 获取延迟信息
	s.Every(1).Minutes().Do(func() {
		go waftask.TaskDelayInfo()

	})
	// 获取参数
	s.Every(1).Minutes().Do(func() {
		go waftask.TaskLoadSetting()

	})

	if global.GWAF_NOTICE_ENABLE {
		// 获取最近token
		s.Every(1).Hour().Do(func() {
			//defer func() {
			//	 zlog.Info("token errr")
			//}()
			zlog.Debug("获取最新token")
			go waftask.TaskWechatAccessToken()

		})
	}

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
					wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]].Mux.Lock()
					wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]].IPWhiteLists = msg.Content.([]model.IPWhiteList)
					zlog.Debug("远程配置", zap.Any("IPWhiteLists", msg.Content.([]model.IPWhiteList)))
					wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]].Mux.Unlock()
					break
				case enums.ChanTypeWhiteURL:
					wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]].Mux.Lock()
					wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]].UrlWhiteLists = msg.Content.([]model.URLWhiteList)
					zlog.Debug("远程配置", zap.Any("UrlWhiteLists", msg.Content.([]model.URLWhiteList)))
					wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]].Mux.Unlock()
					break
				case enums.ChanTypeBlockIP:
					wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]].Mux.Lock()
					wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]].IPBlockLists = msg.Content.([]model.IPBlockList)
					zlog.Debug("远程配置", zap.Any("IPBlockLists", msg))
					wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]].Mux.Unlock()
					break
				case enums.ChanTypeBlockURL:
					wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]].Mux.Lock()
					wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]].UrlBlockLists = msg.Content.([]model.URLBlockList)
					zlog.Debug("远程配置", zap.Any("UrlBlockLists", msg.Content.([]model.URLBlockList)))
					wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]].Mux.Unlock()
					break
				case enums.ChanTypeLdp:
					wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]].Mux.Lock()
					wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]].LdpUrlLists = msg.Content.([]model.LDPUrl)
					zlog.Debug("远程配置", zap.Any("LdpUrlLists", msg.Content.([]model.LDPUrl)))
					wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]].Mux.Unlock()
					break
				case enums.ChanTypeRule:
					wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]].Mux.Lock()
					wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]].RuleData = msg.Content.([]model.Rules)
					wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]].Rule.LoadRules(msg.Content.([]model.Rules))
					zlog.Debug("远程配置", zap.Any("Rule", msg.Content.([]model.Rules)))
					wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]].Mux.Unlock()
					break
				case enums.ChanTypeAnticc:
					wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]].Mux.Lock()
					wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]].PluginIpRateLimiter = plugin.NewIPRateLimiter(rate.Limit(msg.Content.(model.AntiCC).Rate), msg.Content.(model.AntiCC).Limit)
					zlog.Debug("远程配置", zap.Any("Anticc", msg.Content.(model.AntiCC)))
					wafEngine.HostTarget[wafEngine.HostCode[msg.HostCode]].Mux.Unlock()
					break
				case enums.ChanTypeHost:
					hosts := msg.Content.([]model.Hosts)
					if len(hosts) == 1 {
						if wafEngine.HostTarget[hosts[0].Host+":"+strconv.Itoa(hosts[0].Port)].RevProxy != nil {
							wafEngine.HostTarget[hosts[0].Host+":"+strconv.Itoa(hosts[0].Port)].RevProxy = nil
							zlog.Debug("主机重新代理", hosts[0].Host+":"+strconv.Itoa(hosts[0].Port))
						}
						wafEngine.LoadHost(hosts[0])
						wafEngine.StartAllProxyServer()
					}
					break
				case enums.ChanTypeDelHost:
					host := msg.Content.(model.Hosts)
					if host.Id != "" {
						wafEngine.RemoveHost(host)
					}
					break
				}

				//end switch
			} else {
				//新增
				switch msg.Type {
				case enums.ChanTypeHost:
					hosts := msg.Content.([]model.Hosts)
					if len(hosts) == 1 {
						hostRunTimeBean := wafEngine.LoadHost(hosts[0])
						wafEngine.StartProxyServer(hostRunTimeBean)
					}
					break
				}

			}
			break
		case engineStatus := <-global.GWAF_CHAN_ENGINE:
			if engineStatus == 1 {
				zlog.Info("准备关闭WAF引擎")
				wafEngine.CloseWaf()
				zlog.Info("准备启动WAF引擎")
				wafEngine.StartWaf()

			}
			break
		case host := <-global.GWAF_CHAN_HOST:
			if wafEngine.HostTarget[host.Host+":"+strconv.Itoa(host.Port)] != nil {
				wafEngine.HostTarget[host.Host+":"+strconv.Itoa(host.Port)].Host.GUARD_STATUS = host.GUARD_STATUS

			}
			zlog.Debug("规则", zap.Any("主机", host))
			break
		case update := <-global.GWAF_CHAN_UPDATE:
			if update == 1 {
				//需要重新启动
				if global.GWAF_RUNTIME_SERVER_TYPE == false {
					zlog.Info("服务形式重启")
					// 获取当前执行文件的路径
					executablePath, err := os.Executable()
					if err != nil {
						fmt.Println("Error:", err)
						return
					}

					// 使用filepath包提取文件名
					//executableName := filepath.Base(executablePath)
					var cmd *exec.Cmd
					cmd = exec.Command(executablePath, "restart")
					cmd.Run()
					// 等待新实例完成
					err = cmd.Wait()
					if err != nil {
						fmt.Println("Error:", err)
						return
					}
				} else {
					zlog.Info("非服务形式升级重启，请在5秒后手工打开")
					time.Sleep(5 * time.Second)
					os.Exit(0)
				}
			}
		}

	}
	zlog.Info("normal program close")
}

// 优雅升级
func (m *wafSystenService) Graceful() {
	//https://github.com/pengge/uranus/blob/main/main.go 预备参考
}

func main() {

	//获取外网IP
	global.GWAF_RUNTIME_IP = utils.GetExternalIp()

	option := service.KeyValue{}
	//windows
	//OnFailure:"restart",
	if runtime.GOOS == "windows" {
		option["OnFailure"] = "restart"
		option["OnFailureDelayDuration"] = "1s"
		option["OnFailureResetPeriod"] = "10"
	} else {
		option["Restart"] = "always"
	}

	// 创建服务对象
	svcConfig := &service.Config{
		Name:        "SamWafService",
		DisplayName: "SamWaf Service",
		Description: "SamWaf is a Web Application Firewall (WAF) By SamWaf.com",
		Option:      option,
	}
	prg := &wafSystenService{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatal(err)
	}

	// 设置服务控制信号处理程序
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, os.Kill, syscall.SIGTERM)

	/*_, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()*/

	//doWork(ctx)

	// 以服务方式运行
	if len(os.Args) > 1 {
		command := os.Args[1]
		err := service.Control(s, command)
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	if service.Interactive() {
		zlog.Info("main general run true")
		global.GWAF_RUNTIME_SERVER_TYPE = service.Interactive()
	} else {
		zlog.Info("main server run false")
		global.GWAF_RUNTIME_SERVER_TYPE = service.Interactive()
	}
	//defer wafsafeclear.SafeClear()
	// 以常规方式运行
	err = s.Run()
	if err != nil {
		log.Fatal(err)
	}

}
