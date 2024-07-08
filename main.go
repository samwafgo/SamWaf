package main

import (
	"SamWaf/cache"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/globalobj"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/plugin"
	"SamWaf/utils"
	"SamWaf/utils/zlog"
	"SamWaf/wafconfig"
	"SamWaf/wafdb"
	"SamWaf/wafenginecore"
	"SamWaf/wafmangeweb"
	"SamWaf/wafreg"
	"SamWaf/wafsafeclear"
	"SamWaf/wafsnowflake"
	"SamWaf/waftask"
	"crypto/tls"
	_ "embed"
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
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	_ "time/tzdata"
)

//go:embed exedata/ip2region.xdb
var Ip2regionBytes []byte // 当前目录，解析为[]byte类型

//go:embed exedata/ldpconfig.yml
var ldpConfig string //隐私防护ldp

//go:embed exedata/public_key.pem
var publicKey string //公钥key

// wafSystenService 实现了 service.Service 接口
type wafSystenService struct{}

var webmanager *wafmangeweb.WafWebManager // web管理端

// Start 是服务启动时调用的方法
func (m *wafSystenService) Start(s service.Service) error {
	zlog.Info("服务启动形式-----Start")
	go m.run()
	return nil
}

// Stop 是服务停止时调用的方法
func (m *wafSystenService) Stop(s service.Service) error {
	zlog.Info("服务形式的 -----stop")
	wafsafeclear.SafeClear()
	m.stopSamWaf()
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

	//加载配置
	wafconfig.LoadAndInitConfig()
	// 获取当前执行文件的路径
	executablePath, err := os.Executable()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	zlog.Info("执行位置:", executablePath)
	global.GWAF_RUNTIME_CURRENT_EXEPATH = executablePath
	//初始化步骤[加载ip数据库]
	// 从嵌入的文件中读取内容

	global.GCACHE_IP_CBUFF = Ip2regionBytes
	global.GWAF_DLP_CONFIG = ldpConfig
	global.GWAF_REG_PUBLIC_KEY = publicKey

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
	zlog.Info("OutIp", global.GWAF_RUNTIME_IP)

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
	globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE = &wafenginecore.WafEngine{
		HostTarget: map[string]*wafenginmodel.HostSafe{},
		//主机和code的关系
		HostCode:     map[string]string{},
		ServerOnline: map[int]innerbean.ServerRunTime{},
		//所有证书情况 对应端口 可能多个端口都是https 443，或者其他非标准端口也要实现https证书
		AllCertificate: map[int]map[string]*tls.Certificate{},

		EngineCurrentStatus: 0, // 当前waf引擎状态
	}
	http.Handle("/", globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE)
	globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.StartWaf()

	//启动管理界面
	webmanager = &wafmangeweb.WafWebManager{}
	go func() {
		webmanager.StartLocalServer()
	}()

	//启动websocket
	global.GWebSocket = model.InitWafWebSocket()
	//定时取规则并更新（考虑后期定时拉取公共规则 待定，可能会影响实际生产）

	//定时器 （后期考虑是否独立包处理）
	timezone, _ := time.LoadLocation("Asia/Shanghai")
	globalobj.GWAF_RUNTIME_OBJ_WAF_CRON = gocron.NewScheduler(timezone)

	global.GWAF_LAST_UPDATE_TIME = time.Now()
	// 每1秒执行qps清空
	globalobj.GWAF_RUNTIME_OBJ_WAF_CRON.Every(1).Seconds().Do(func() {
		// 清零计数器
		atomic.StoreUint64(&global.GWAF_RUNTIME_QPS, 0)
		atomic.StoreUint64(&global.GWAF_RUNTIME_LOG_PROCESS, 0)
	})
	go waftask.TaskShareDbInfo()
	// 执行分库操作 （每天凌晨3点进行数据归档操作）
	globalobj.GWAF_RUNTIME_OBJ_WAF_CRON.Every(1).Day().At("03:00").Do(func() {
		if global.GDATA_CURRENT_CHANGE == false {
			go waftask.TaskShareDbInfo()
		} else {
			zlog.Debug("执行分库操作没完成，调度任务PASS")
		}
	})

	// 每10秒执行一次
	globalobj.GWAF_RUNTIME_OBJ_WAF_CRON.Every(10).Seconds().Do(func() {
		if global.GWAF_SWITCH_TASK_COUNTER == false {
			go waftask.TaskCounter()
		} else {
			zlog.Debug("统计还没完成，调度任务PASS")
		}
	})
	// 获取延迟信息
	globalobj.GWAF_RUNTIME_OBJ_WAF_CRON.Every(1).Minutes().Do(func() {
		go waftask.TaskDelayInfo()

	})
	// 获取参数
	globalobj.GWAF_RUNTIME_OBJ_WAF_CRON.Every(1).Minutes().Do(func() {
		go waftask.TaskLoadSetting()

	})

	if global.GWAF_NOTICE_ENABLE {
		// 获取最近token
		globalobj.GWAF_RUNTIME_OBJ_WAF_CRON.Every(1).Hour().Do(func() {
			//defer func() {
			//	 zlog.Info("token errr")
			//}()
			zlog.Debug("获取最新token")
			go waftask.TaskWechatAccessToken()

		})
	}
	// 每天早晚8点进行数据汇总通知
	globalobj.GWAF_RUNTIME_OBJ_WAF_CRON.Every(1).Day().At("08:00;20:00").Do(func() {
		go waftask.TaskStatusNotify()
	})

	// 每天早5点删除历史信息
	globalobj.GWAF_RUNTIME_OBJ_WAF_CRON.Every(1).Day().At("05:00").Do(func() {
		go waftask.TaskDeleteHistoryInfo()
	})
	globalobj.GWAF_RUNTIME_OBJ_WAF_CRON.StartAsync()

	//脱敏处理初始化
	global.GWAF_DLP, _ = dlp.NewEngine("wafDlp")
	err = global.GWAF_DLP.ApplyConfig(ldpConfig)
	if err != nil {
		zlog.Info("ldp init error", err)
	} else {
		// 注册自定义脱敏规则
		global.GWAF_DLP.RegisterMasker("LoginSensitiveInfoMaskRule", func(in string) (string, error) {

			// 分割成键值对
			pairs := strings.Split(in, "&")
			// 遍历每个键值对，对值进行脱敏处理
			for i, pair := range pairs {
				keyValue := strings.SplitN(pair, "=", 2)
				if len(keyValue) != 2 {
					continue
				}
				value := keyValue[1]
				if len(value) > 2 {
					value = value[:1] + strings.Repeat("*", len(value)-2) + value[len(value)-1:]
				}
				pairs[i] = keyValue[0] + "=" + value
			}
			// 将处理后的键值对重新组合成字符串
			return "【已脱敏】" + strings.Join(pairs, "&"), nil
		})

	}

	/*withEncrypt, err :=wafreg.GenClientMachineInfoWithEncrypt()
	if err != nil {
		fmt.Println("获取机器码失败")
	} else {
		fmt.Println("机器码: ", withEncrypt)
	}*/
	//加载授权信息
	verifyResult, info, err := wafreg.VerifyServerReg()
	if verifyResult {
		global.GWAF_REG_INFO = info
		zlog.Debug("授权信息 调试信息", info)
		expiryDay, isExpiry := wafreg.CheckExpiry(info.ExpiryDate)
		if isExpiry {
			zlog.Info("授权信息已经过期")
		} else {
			zlog.Info("授权信息还剩余:" + strconv.Itoa(expiryDay) + "天")
		}
	} else {
		zlog.Info("授权信息无效", err)
	}
	// 上传客户端信息到中心节点
	globalobj.GWAF_RUNTIME_OBJ_WAF_CRON.Every(1).Minutes().Do(func() {
		go waftask.TaskClientToCenter()
	})

	for {
		select {
		case msg := <-global.GWAF_CHAN_MSG:
			if globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]] != nil && globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode] != "" {
				switch msg.Type {
				case enums.ChanTypeWhiteIP:
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].Mux.Lock()
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].IPWhiteLists = msg.Content.([]model.IPWhiteList)
					zlog.Debug("远程配置", zap.Any("IPWhiteLists", msg.Content.([]model.IPWhiteList)))
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].Mux.Unlock()
					break
				case enums.ChanTypeWhiteURL:
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].Mux.Lock()
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].UrlWhiteLists = msg.Content.([]model.URLWhiteList)
					zlog.Debug("远程配置", zap.Any("UrlWhiteLists", msg.Content.([]model.URLWhiteList)))
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].Mux.Unlock()
					break
				case enums.ChanTypeBlockIP:
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].Mux.Lock()
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].IPBlockLists = msg.Content.([]model.IPBlockList)
					zlog.Debug("远程配置", zap.Any("IPBlockLists", msg))
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].Mux.Unlock()
					break
				case enums.ChanTypeBlockURL:
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].Mux.Lock()
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].UrlBlockLists = msg.Content.([]model.URLBlockList)
					zlog.Debug("远程配置", zap.Any("UrlBlockLists", msg.Content.([]model.URLBlockList)))
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].Mux.Unlock()
					break
				case enums.ChanTypeLdp:
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].Mux.Lock()
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].LdpUrlLists = msg.Content.([]model.LDPUrl)
					zlog.Debug("远程配置", zap.Any("LdpUrlLists", msg.Content.([]model.LDPUrl)))
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].Mux.Unlock()
					break
				case enums.ChanTypeRule:
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].Mux.Lock()
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].RuleData = msg.Content.([]model.Rules)
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].Rule.LoadRules(msg.Content.([]model.Rules))
					zlog.Debug("远程配置", zap.Any("Rule", msg.Content.([]model.Rules)))
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].Mux.Unlock()
					break
				case enums.ChanTypeAnticc:
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].Mux.Lock()
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].PluginIpRateLimiter = plugin.NewIPRateLimiter(rate.Limit(msg.Content.(model.AntiCC).Rate), msg.Content.(model.AntiCC).Limit)
					zlog.Debug("远程配置", zap.Any("Anticc", msg.Content.(model.AntiCC)))
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].Mux.Unlock()
					break
				case enums.ChanTypeHost:
					hosts := msg.Content.([]model.Hosts)
					if len(hosts) == 1 {
						//情况1，端口是新的，域名也是新的
						//情况2，端口不变,域名也不变，就是重新加载数据
						//情况3，端口从A切换到B了，域名是旧的 ；端口更改后当前这个端口下没有域名了，应该是关闭了，并移除数据

						//情况1
						if msg.OldContent == nil {
							zlog.Debug("主机处理情况1 端口是新的，域名也是新的")
							globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.LoadHost(hosts[0])
							globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.StartAllProxyServer()
						} else {
							hostsOld := msg.OldContent.(model.Hosts)
							if hosts[0].Host == hostsOld.Host && hosts[0].Port == hostsOld.Port {
								//情况2
								zlog.Debug("主机处理情况2 端口不变,域名也不变，就是重新加载数据")
								if globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[hosts[0].Host+":"+strconv.Itoa(hosts[0].Port)] != nil &&
									globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[hosts[0].Host+":"+strconv.Itoa(hosts[0].Port)].RevProxy != nil {
									//设置空代理
									globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[hosts[0].Host+":"+strconv.Itoa(hosts[0].Port)].RevProxy = nil
									zlog.Debug("主机重新代理", hosts[0].Host+":"+strconv.Itoa(hosts[0].Port))
								}
								//如果本次是关闭，那么应该关闭主机
								if hosts[0].START_STATUS == 1 {
									globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.RemoveHost(hosts[0])
								}
								globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.LoadHost(hosts[0])
								globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.StartAllProxyServer()
							} else if hosts[0].Host == hostsOld.Host && hosts[0].Port != hostsOld.Port {
								//情况3
								zlog.Debug("主机处理情况3 端口从A切换到B了，域名是旧的 ；端口更改后当前这个端口下没有域名了，应该是关闭了，并移除数据")
								if globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[hostsOld.Host+":"+strconv.Itoa(hostsOld.Port)] != nil &&
									globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[hostsOld.Host+":"+strconv.Itoa(hostsOld.Port)].RevProxy != nil {
									globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[hostsOld.Host+":"+strconv.Itoa(hostsOld.Port)].RevProxy = nil
								}
								globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.RemoveHost(hostsOld)
								globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.LoadHost(hosts[0])
								globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.StartAllProxyServer()
							}
						}

					}
					break
				case enums.ChanTypeDelHost:
					host := msg.Content.(model.Hosts)
					if host.Id != "" {
						globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.RemoveHost(host)
						globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.EnumAllPortProxyServer()
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
						hostRunTimeBean := globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.LoadHost(hosts[0])
						globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.StartProxyServer(hostRunTimeBean)
					}
					break
				}

			}
			break
		case engineStatus := <-global.GWAF_CHAN_ENGINE:
			if engineStatus == 1 {
				zlog.Info("准备关闭WAF引擎")
				globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.CloseWaf()
				zlog.Info("准备启动WAF引擎")
				globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.StartWaf()

			}
			break
		case host := <-global.GWAF_CHAN_HOST:
			if globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[host.Host+":"+strconv.Itoa(host.Port)] != nil {
				globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[host.Host+":"+strconv.Itoa(host.Port)].Host.GUARD_STATUS = host.GUARD_STATUS

			}
			zlog.Debug("规则", zap.Any("主机", host))
			break
		case update := <-global.GWAF_CHAN_UPDATE:
			if update == 1 {
				global.GWAF_RUNTIME_SERVER_TYPE = !service.Interactive()
				//需要重新启动
				if global.GWAF_RUNTIME_SERVER_TYPE == true {
					zlog.Info("服务形式重启")

					m.stopSamWaf()
					// 使用filepath包提取文件名
					//executableName := filepath.Base(executablePath)
					var cmd *exec.Cmd
					cmd = exec.Command(global.GWAF_RUNTIME_CURRENT_EXEPATH, "restart")
					err = cmd.Start()
					if err != nil {
						zlog.Error("Service Error restarting program:", err)
						return
					}
					// 等待新版本程序启动
					time.Sleep(2 * time.Second)
					os.Exit(0)
				} else {

					m.stopSamWaf()
					cmd := exec.Command(global.GWAF_RUNTIME_CURRENT_EXEPATH)
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stderr
					err := cmd.Start()
					if err != nil {
						zlog.Error("Not Service Error restarting program:", err)
						return
					}
					// 等待新版本程序启动
					time.Sleep(2 * time.Second)
					os.Exit(0)
				}
			}
		}

	}
	zlog.Info("normal program close")
}

// 停止要提前关闭的 是服务的主要逻辑
func (m *wafSystenService) stopSamWaf() {
	zlog.Debug("Shutdown SamWaf Engine...")
	globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.CloseWaf()
	zlog.Debug("Shutdown SamWaf Engine finished")

	zlog.Debug("Shutdown SamWaf Cron...")
	globalobj.GWAF_RUNTIME_OBJ_WAF_CRON.Stop()
	zlog.Debug("Shutdown SamWaf Cron finished")

	zlog.Debug("Shutdown SamWaf WebManager...")
	webmanager.CloseLocalServer()
	zlog.Debug("Shutdown SamWaf WebManager finished")

}

// 优雅升级
func (m *wafSystenService) Graceful() {
	//https://github.com/pengge/uranus/blob/main/main.go 预备参考
}

func main() {
	if v := recover(); v != nil { // 侦测到一个恐慌
		zlog.Info("主流程上被异常了")
	}
	pid := os.Getpid()
	zlog.Debug("SamWaf Current PID:" + strconv.Itoa(pid))
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
		zlog.Info("main server under service manager")
		global.GWAF_RUNTIME_SERVER_TYPE = service.Interactive()
	} else {
		zlog.Info("main server not under service manager")
		global.GWAF_RUNTIME_SERVER_TYPE = service.Interactive()
	}
	//defer wafsafeclear.SafeClear()
	// 以常规方式运行
	err = s.Run()
	if err != nil {
		log.Fatal(err)
	}

}
