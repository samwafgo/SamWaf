package main

import (
	"SamWaf/cache"
	"SamWaf/common/gwebsocket"
	"SamWaf/common/tasklog"
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/globalobj"
	"SamWaf/innerbean"
	"SamWaf/iplocation"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/plugin"
	"SamWaf/supervisor"
	"SamWaf/utils"
	"SamWaf/wafai"
	"SamWaf/wafappengine"
	"SamWaf/wafconfig"
	"SamWaf/wafdb"
	"SamWaf/wafenginecore"
	"SamWaf/wafenginecore/wafcaptcha"
	"SamWaf/wafinit"
	"SamWaf/wafipban"
	"SamWaf/wafipc"
	"SamWaf/wafmangeweb"
	"SamWaf/wafnotify"
	"SamWaf/wafowasp"
	"SamWaf/wafqueue"
	"SamWaf/wafreg"
	"SamWaf/wafsafeclear"
	"SamWaf/wafsnowflake"
	"SamWaf/waftask"
	"SamWaf/waftunnelengine"
	"SamWaf/wafupdate"
	"crypto/tls"
	"embed"
	_ "embed"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata"

	dlp "github.com/bytedance/godlp"
	"github.com/kardianos/service"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gorm.io/gorm"
)

//go:embed exedata/ip2region.xdb
var Ip2regionBytes []byte // 当前目录，解析为[]byte类型

//go:embed exedata/GeoLite2-Country.mmdb
var Ipv6CountryBytes []byte // IPv6国家解析

//go:embed exedata/ldpconfig.yml
var ldpConfig string //隐私防护ldp

//go:embed exedata/public_key.pem
var publicKey string //公钥key

//go:embed exedata/owasp
var owaspAssets embed.FS

//go:embed exedata/spiderbot
var spiderBotAssets embed.FS

//go:embed exedata/captcha
var captchaAssets embed.FS

//go:embed exedata/capjs
var capjs embed.FS

//go:embed exedata/httpauth
var httpauth embed.FS

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
	m.Graceful()
	return nil
}

// 守护协程
func NeverExit(name string, f func()) {
	defer func() {
		if v := recover(); v != nil {
			zlog.Error(fmt.Sprintf("协程%s崩溃了，准备重启一个。 : %v, Stack Trace: %s", name, v, debug.Stack()))
			if global.GWAF_RELEASE == "false" {
				debug.PrintStack()
			}

			go NeverExit(name, f) // 重启一个同功能协程
		}
	}()
	zlog.Info(name + " start")
	f()
}

// run 是服务的主要逻辑
func (m *wafSystenService) run() {

	// 先尝试监听端口，检查是否被占用。
	// 升级接管(takeover)模式下旧 Worker 仍持有管理端口 :26666，新 Worker 预期与其并存，故跳过该探测。
	if !global.GWAF_RUNTIME_IS_TAKEOVER {
		listener, err := net.Listen("tcp", ":"+strconv.Itoa(global.GWAF_LOCAL_SERVER_PORT))
		if err != nil {
			errMsg := fmt.Sprintf("管理界面端口 %d 已被占用，请检查并修改配置(conf/config.yml local_port字段)或关闭占用该端口的程序: %s",
				global.GWAF_LOCAL_SERVER_PORT, err.Error())
			zlog.Error(errMsg)
			panic(errMsg)
		}
		if listener != nil {
			listener.Close()
		}
	}
	// 获取当前执行文件的路径
	executablePath, err := os.Executable()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	zlog.Info("执行位置:", executablePath)
	global.GWAF_RUNTIME_CURRENT_EXEPATH = executablePath
	//初始化步骤[加载ip数据库]
	// 创建 IP Location Manager
	global.GIPLOCATION_MANAGER = iplocation.NewManager()

	// 加载 IPv4 数据库
	ip2RegionFilePath := filepath.Join(utils.GetCurrentDir(), "data", "ip2region.xdb")
	var ipv4Data []byte
	if _, err := os.Stat(ip2RegionFilePath); os.IsNotExist(err) {
		// 使用内置数据
		ipv4Data = Ip2regionBytes
		zlog.Info("Using embedded IPv4 database, size: ", len(ipv4Data))
	} else {
		// 读取外部文件
		fileBytes, err := ioutil.ReadFile(ip2RegionFilePath)
		if err != nil {
			log.Fatalf("Failed to read IP database file ip2region.xdb: %v", err)
		}
		ipv4Data = fileBytes
		zlog.Info("IPv4 database ip2region.xdb loaded from file, size: ", len(ipv4Data), ip2RegionFilePath)
	}

	// 根据配置加载 IPv4 数据库
	if global.GCONFIG_IP_V4_SOURCE == "ip2region" {
		err := global.GIPLOCATION_MANAGER.LoadV4Ip2Region(ipv4Data, iplocation.DBFormat(global.GCONFIG_IP_V4_FORMAT))
		if err != nil {
			log.Fatalf("Failed to load IPv4 ip2region database: %v", err)
		}
		zlog.Info("IPv4 ip2region database loaded successfully")
	} else if global.GCONFIG_IP_V4_SOURCE == "geolite2" {
		err := global.GIPLOCATION_MANAGER.LoadV4GeoLite2(ipv4Data)
		if err != nil {
			log.Fatalf("Failed to load IPv4 GeoLite2 database: %v", err)
		}
		zlog.Info("IPv4 GeoLite2 database loaded successfully")
	} else if global.GCONFIG_IP_V4_SOURCE == "ipdb" {
		ipdbPath := filepath.Join(utils.GetCurrentDir(), "data", "iplocation.ipdb")
		if _, err := os.Stat(ipdbPath); err == nil {
			if err2 := global.GIPLOCATION_MANAGER.LoadIpdb(ipdbPath); err2 != nil {
				zlog.Warn("Failed to load ipdb database (v4): ", err2)
			} else {
				zlog.Info("ipdb database loaded successfully (v4 source)")
			}
		} else {
			zlog.Warn("ipdb database file not found, please upload iplocation.ipdb")
		}
	}

	// 加载 IPv6 数据库
	if global.GCONFIG_IP_V6_SOURCE == "ip2region" {
		// IPv6 ip2region 需要单独的文件
		ipv6Ip2RegionPath := filepath.Join(utils.GetCurrentDir(), "data", "ip2region_v6.xdb")
		if _, err := os.Stat(ipv6Ip2RegionPath); err == nil {
			fileBytes, err := ioutil.ReadFile(ipv6Ip2RegionPath)
			if err != nil {
				zlog.Warn("Failed to read IPv6 ip2region database file: ", err)
			} else {
				err = global.GIPLOCATION_MANAGER.LoadV6Ip2Region(fileBytes, iplocation.DBFormat(global.GCONFIG_IP_V6_FORMAT))
				if err != nil {
					zlog.Warn("Failed to load IPv6 ip2region database: ", err)
				} else {
					zlog.Info("IPv6 ip2region database loaded successfully, size: ", len(fileBytes))
				}
			}
		} else {
			zlog.Warn("IPv6 ip2region database file not found, please upload ip2region_v6.xdb")
		}
	} else if global.GCONFIG_IP_V6_SOURCE == "geolite2" {
		// IPv6 GeoLite2
		ipv6GeoLitePath := filepath.Join(utils.GetCurrentDir(), "data", "GeoLite2-Country.mmdb")
		var ipv6Data []byte
		if _, err := os.Stat(ipv6GeoLitePath); os.IsNotExist(err) {
			// 使用内置数据
			ipv6Data = Ipv6CountryBytes
			zlog.Info("Using embedded IPv6 GeoLite2 database, size: ", len(ipv6Data))
		} else {
			// 读取外部文件
			fileBytes, err := ioutil.ReadFile(ipv6GeoLitePath)
			if err != nil {
				log.Fatalf("Failed to read IPv6 GeoLite2 database file: %v", err)
			}
			ipv6Data = fileBytes
			zlog.Info("IPv6 GeoLite2 database loaded from file, size: ", len(ipv6Data), ipv6GeoLitePath)
		}

		err := global.GIPLOCATION_MANAGER.LoadV6GeoLite2(ipv6Data)
		if err != nil {
			log.Fatalf("Failed to load IPv6 GeoLite2 database: %v", err)
		}
		zlog.Info("IPv6 GeoLite2 database loaded successfully")
	} else if global.GCONFIG_IP_V6_SOURCE == "ipdb" {
		// 如果 v4 已经加载了 ipdb，跳过重复加载
		if !global.GIPLOCATION_MANAGER.IsIpdbLoaded() {
			ipdbPath := filepath.Join(utils.GetCurrentDir(), "data", "iplocation.ipdb")
			if _, err := os.Stat(ipdbPath); err == nil {
				if err2 := global.GIPLOCATION_MANAGER.LoadIpdb(ipdbPath); err2 != nil {
					zlog.Warn("Failed to load ipdb database (v6): ", err2)
				} else {
					zlog.Info("ipdb database loaded successfully (v6 source)")
				}
			} else {
				zlog.Warn("ipdb database file not found, please upload iplocation.ipdb")
			}
		} else {
			zlog.Info("ipdb database already loaded (shared with v4)")
		}
	}
	global.GWAF_DLP_CONFIG = ldpConfig
	global.GWAF_REG_PUBLIC_KEY = publicKey

	//初始化AI智能检测器，若存在已上传的模型包则加载（失败安全，不影响启动）
	global.GWAF_AI_DETECTOR = wafai.NewDetector()
	aiModelPath := filepath.Join(utils.GetCurrentDir(), "data", "ai_model", "current.swai")
	if _, err := os.Stat(aiModelPath); err == nil {
		if manifest, err := global.GWAF_AI_DETECTOR.LoadFromFile(aiModelPath); err != nil {
			zlog.Warn("AI模型加载失败，AI检测将不可用: ", err.Error())
		} else {
			zlog.Info(fmt.Sprintf("AI模型加载成功: version=%s feature=%s type=%s",
				manifest.ModelVersion, manifest.FeatureVersion, manifest.ModelType))
		}
	}

	//owasp资源 释放
	err = wafinit.CheckAndReleaseDataset(owaspAssets, utils.GetCurrentDir()+"/data/owasp", "owasp")
	if err != nil {
		zlog.Error("owasp", err.Error())
	}

	// 验证码资源释放
	err = wafinit.CheckAndReleaseDataset(captchaAssets, utils.GetCurrentDir()+"/data/captcha", "captcha")
	if err != nil {
		zlog.Error("captcha", err.Error())
	}
	// 验证码工作量证明资源释放
	err = wafinit.CheckAndReleaseDataset(capjs, utils.GetCurrentDir()+"/data/capjs", "capjs")
	if err != nil {
		zlog.Error("capJs", err.Error())
	}

	// HTTP认证登录页面资源释放
	err = wafinit.CheckAndReleaseDataset(httpauth, utils.GetCurrentDir()+"/data/httpauth", "httpauth")
	if err != nil {
		zlog.Error("httpauth", err.Error())
	}
	//TODO 准备释放最新spider bot

	//初始化cache
	{
		cacheStore, err := cache.NewCacheStore(global.GCACHE_TYPE, &cache.RedisCacheConfig{
			Host:     global.GCACHE_REDIS_HOST,
			Port:     global.GCACHE_REDIS_PORT,
			Password: global.GCACHE_REDIS_PASSWORD,
			DB:       global.GCACHE_REDIS_DB,
		})
		if err != nil {
			zlog.Error("初始化缓存失败，程序退出，请检查conf/config.yml缓存配置是否正确", "error", err)
			os.Exit(1)
		}
		global.GCACHE_WAFCACHE = cacheStore
	}
	//初始化验证码服务
	wafcaptcha.InitCaptchaService(global.GCACHE_WAFCACHE)
	//初始化锁写不锁度
	global.GWAF_MEASURE_PROCESS_DEQUEENGINE = cache.InitWafOnlyLockWrite()
	// 创建 Snowflake 实例
	global.GWAF_SNOWFLAKE_GEN = wafsnowflake.NewSnowflake(1609459200000, 1, 1) // 设置epoch时间、机器ID和数据中心ID

	// 创建owasp 管理器（支持热重载）
	global.GWAF_OWASP_MANAGER = wafowasp.NewOwaspManager(utils.GetCurrentDir())
	global.GWAF_OWASP = global.GWAF_OWASP_MANAGER.Current()
	// 注入升级上下文：避免 wafowasp → global 的循环依赖
	wafowasp.ConfigureUpgrader(wafowasp.UpgradeConfig{
		UpdateVersionURL: global.GUPDATE_VERSION_URL,
		NotifyFunc: func(success bool, msg string) {
			if global.GQEQUE_MESSAGE_DB == nil {
				return
			}
			successStr := "false"
			if success {
				successStr = "true"
			}
			global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.UpdateResultMessageInfo{
				BaseMessageInfo: innerbean.BaseMessageInfo{
					OperaType: "OWASP 规则升级",
					Server:    global.GWAF_CUSTOM_SERVER_NAME,
				},
				Msg:     msg,
				Success: successStr,
			})
		},
	})

	// 初始化ip ban
	wafipban.InitIPBanManager(global.GCACHE_WAFCACHE)

	//提前初始化
	global.GDATA_CURRENT_LOG_DB_MAP = map[string]*gorm.DB{}
	rversion := "初始化系统 编译器版本:" + runtime.Version() + " 程序版本号：" + global.GWAF_RELEASE_VERSION_NAME + "(" + global.GWAF_RELEASE_VERSION + ")"
	if global.GWAF_RELEASE == "false" {
		rversion = rversion + " 调试版本"
	} else {
		rversion = rversion + " 发行版本"
	}
	if runtime.GOOS == "linux" {
		rversion = rversion + " linux"
	} else if runtime.GOOS == "windows" {
		rversion = rversion + " windows"
		if utils.IsSupportedWindows7Version() {
			zlog.Info("Now your system is win7 or win2008r2.")
		}
		if global.GWAF_RUNTIME_WIN7_VERSION == "true" && utils.IsSupportedWindows7Version() == false {
			zlog.Error("Now your use is win7 or win2008r2 special version，We recommend you download normal version")
		}
	} else {
		rversion = rversion + "  " + runtime.GOOS
	}
	if global.GWAF_RUNTIME_WIN7_VERSION == "true" {
		rversion = rversion + " Win7内核版本"
	}
	rversion = rversion + " plat:" + runtime.GOOS + "-" + runtime.GOARCH
	zlog.Info(rversion)
	zlog.Info("OutIp", global.GWAF_RUNTIME_IP)

	if global.GWAF_RELEASE == "false" {
		global.GUPDATE_VERSION_URL = "http://127.0.0.1:8111/"
	}

	//初始化本地数据库
	if _, err := wafdb.InitCoreDb(""); err != nil {
		zlog.Error("初始化核心数据库失败，程序退出，请检查conf/config.yml数据库配置是否正确", "error", err)
		os.Exit(1)
	}
	if _, err := wafdb.InitLogDb(""); err != nil {
		zlog.Error("初始化日志数据库失败，程序退出，请检查conf/config.yml数据库配置是否正确", "error", err)
		os.Exit(1)
	}
	if _, err := wafdb.InitStatsDb(""); err != nil {
		zlog.Error("初始化统计数据库失败，程序退出，请检查conf/config.yml数据库配置是否正确", "error", err)
		os.Exit(1)
	}

	//初始化插件系统（从配置文件加载）
	if err := plugin.InitPluginSystem(); err != nil {
		zlog.Error("初始化插件系统失败", "error", err)
		// 插件系统初始化失败不影响主程序启动
	}

	//初始化队列引擎
	wafqueue.InitDequeEngine()
	//启动队列消费
	go NeverExit("ProcessCoreDequeEngine", wafqueue.ProcessCoreDequeEngine)
	go NeverExit("ProcessMessageDequeEngine", wafqueue.ProcessMessageDequeEngine)
	go NeverExit("ProcessStatDequeEngine", wafqueue.ProcessStatDequeEngine)
	go NeverExit("ProcessLogDequeEngine", wafqueue.ProcessLogDequeEngine)

	//初始化一次系统参数信息
	waftask.TaskLoadSetting(true)
	// 初始化任务日志管理器（需在 TaskLoadSetting 后执行，以获取正确的 retainDays 配置）
	taskLogDir := filepath.Join(utils.GetCurrentDir(), "logs", "task")
	tasklog.InitGlobalTaskLogManager(taskLogDir, int(global.GCONFIG_TASK_LOG_RETAIN_DAYS))
	// 将 TaskZapCore 挂到全局 zlog，使任务执行期间的 zlog 输出同步写入任务日志文件
	zlog.AddCore(tasklog.NewTaskZapCore(zapcore.DebugLevel))
	//启动通知相关程序
	global.GNOTIFY_KAKFA_SERVICE = wafnotify.InitNotifyKafkaEngine(global.GCONFIG_RECORD_KAFKA_ENABLE, global.GCONFIG_RECORD_KAFKA_URL, global.GCONFIG_RECORD_KAFKA_TOPIC) //kafka
	// 日志文件写入
	compressFlag := global.GCONFIG_LOG_FILE_WRITE_COMPRESS == 1
	global.GNOTIFY_LOG_FILE_WRITER = wafnotify.InitLogFileWriterEngine(
		global.GCONFIG_LOG_FILE_WRITE_ENABLE,
		global.GCONFIG_LOG_FILE_WRITE_PATH,
		global.GCONFIG_LOG_FILE_WRITE_FORMAT,
		global.GCONFIG_LOG_FILE_WRITE_CUSTOM_TPL,
		global.GCONFIG_LOG_FILE_WRITE_MAX_SIZE,
		int(global.GCONFIG_LOG_FILE_WRITE_MAX_BACKUPS),
		int(global.GCONFIG_LOG_FILE_WRITE_MAX_DAYS),
		compressFlag,
	)
	//启动waf
	globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE = &wafenginecore.WafEngine{
		//路由表(HostTarget/HostCode/HostTargetNoPort/HostTargetMoreDomain)改为 RCU 快照，
		//下方 InitRouting() 初始化为空表；读走 rt()，写走 copy-on-write 助手。
		ServerOnline: wafenginmodel.NewSafeServerMap(),
		//所有证书情况 对应端口 可能多个端口都是https 443，或者其他非标准端口也要实现https证书
		AllCertificate: wafenginecore.AllCertificate{
			Mux: sync.Mutex{},
			Map: map[string]*tls.Certificate{},
		},
		EngineCurrentStatus: 0, // 当前waf引擎状态
		Sensitive:           make([]model.Sensitive, 0),
		PluginManager:       globalobj.GWAF_RUNTIME_OBJ_PLUGIN_MANAGER, // 设置插件管理器
	}
	//初始化路由快照(RCU 空表)，之后 StartWaf→LoadAllHost 通过 copy-on-write 填充
	globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.InitRouting()
	http.Handle("/", globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE)
	globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.StartWaf()

	//启动隧道
	globalobj.GWAF_RUNTIME_OBJ_TUNNEL_ENGINE = waftunnelengine.NewWafTunnelEngine()
	//启动应用管理引擎
	globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE = wafappengine.NewWafAppEngine()
	// 隧道/应用是独占型单例(独占端口/外部进程)，不能与旧 Worker 并存。
	// takeover 升级模式下延迟到旧 Worker 退出后由 Supervisor 的 ACTIVATE 触发接管（见 activateSingletons）。
	if !global.GWAF_RUNTIME_IS_TAKEOVER {
		globalobj.GWAF_RUNTIME_OBJ_TUNNEL_ENGINE.StartTunnel()
		globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE.StartApps()
	} else {
		zlog.Info("[Worker] takeover 模式：暂不启动隧道/应用，等待旧 Worker 退出后由 Supervisor 的 ACTIVATE 接管")
	}
	//启动管理界面
	webmanager = &wafmangeweb.WafWebManager{LogName: "WebManager"}
	go func() {
		webmanager.StartLocalServer()
	}()

	//启动websocket
	global.GWebSocket = gwebsocket.InitWafWebSocket()
	//定时取规则并更新（考虑后期定时拉取公共规则 待定，可能会影响实际生产）

	// 创建任务调度器

	global.GWAF_LAST_UPDATE_TIME = time.Now()

	//开始 需要添加到任务注册器里面的
	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskRegistry = waftask.NewTaskRegistry()
	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskRegistry.RegisterTask(enums.TASK_RUNTIME_QPS_CLEAN, waftask.TaskLogQpsClean)
	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskRegistry.RegisterTask(enums.TASK_HOST_QPS_CLEAN, waftask.TaskHostQpsClean)
	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskRegistry.RegisterTask(enums.TASK_SHARE_DB, waftask.TaskShareDbInfo)
	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskRegistry.RegisterTask(enums.TASK_COUNTER, waftask.TaskCounter)
	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskRegistry.RegisterTask(enums.TASK_DELAY_INFO, waftask.TaskDelayInfo)
	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskRegistry.RegisterTask(enums.TASK_LOAD_CONFIG, waftask.TaskLoadSettingCron)
	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskRegistry.RegisterTask(enums.TASK_REFLUSH_WECHAT_ACCESS_TOKEN, waftask.TaskWechatAccessToken)
	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskRegistry.RegisterTask(enums.TASK_DELETE_HISTORY_INFO, waftask.TaskDeleteHistoryInfo)
	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskRegistry.RegisterTask(enums.TASK_DELETE_HISTORY_DOWNLOAD_FILE, waftask.TaskHistoryDownload)
	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskRegistry.RegisterTask(enums.TASK_SSL_ORDER_RENEW, waftask.SSLOrderReload)
	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskRegistry.RegisterTask(enums.TASK_SSL_PATH_LOAD, waftask.SSLReload)
	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskRegistry.RegisterTask(enums.TASK_BATCH, waftask.BatchTask)
	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskRegistry.RegisterTask(enums.TASK_SSL_EXPIRE_CHECK, waftask.SSLExpireCheck)
	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskRegistry.RegisterTask(enums.TASK_NOTICE, waftask.TaskStatusNotify)
	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskRegistry.RegisterTask(enums.TASK_HEALTH, waftask.TaskHealth)
	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskRegistry.RegisterTask(enums.TASK_CLEAR_CC_WINDOWS, waftask.TaskCC)
	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskRegistry.RegisterTask(enums.TASK_CLEAR_WEBCACHE, waftask.TaskClearWebcache)
	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskRegistry.RegisterTask(enums.TASK_GC, waftask.TaskGC)
	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskRegistry.RegisterTask(enums.TASK_STATS_PUSH, waftask.TaskStatsPush)
	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskRegistry.RegisterTask(enums.TASK_DB_MONITOR, waftask.TaskDatabaseMonitor)
	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskRegistry.RegisterTask(enums.TASK_FIREWALL_CLEAN_EXPIRED, waftask.TaskFirewallCleanExpired)
	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskRegistry.RegisterTask(enums.TASK_STATS_DATA_CLEANUP, waftask.TaskStatsDataCleanup)

	go waftask.TaskShareDbInfo()

	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskScheduler = waftask.NewTaskScheduler(globalobj.GWAF_RUNTIME_OBJ_WAF_TaskRegistry)
	taskDbList := waftask.InitTaskDb()
	for _, task := range taskDbList {
		globalobj.GWAF_RUNTIME_OBJ_WAF_TaskScheduler.ScheduleTask(task.TaskUnit, task.TaskValue, task.TaskAt, task.TaskMethod, task.TaskDaysOfTheWeek)
	}
	//结束 需要添加到任务注册器里面的
	// cron 任务调度同样是单例（避免新旧 Worker 重复执行定时任务）；takeover 模式延迟到 ACTIVATE 再启动。
	if !global.GWAF_RUNTIME_IS_TAKEOVER {
		globalobj.GWAF_RUNTIME_OBJ_WAF_TaskScheduler.Start()
	}

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
	//加载授权信息
	verifyResult, info, err := wafreg.VerifyServerRegByDefaultFile()
	if verifyResult {
		global.GWAF_REG_INFO = info
		zlog.Debug("授权信息 调试信息", info)
		expiryDay, isExpiry := wafreg.CheckExpiry(info.ExpiryDate)
		if isExpiry {
			global.GWAF_REG_INFO.IsExpiry = true
			zlog.Info("授权信息已经过期")
		} else {
			global.GWAF_REG_INFO.IsExpiry = false
			zlog.Info("授权信息还剩余:" + strconv.Itoa(expiryDay) + "天")
		}
	} else {
		zlog.Info("regInfo", err)
	}

	if global.GWAF_SECURITY_ENTRY_ENABLE && global.GWAF_SECURITY_ENTRY_PATH != "" {
		zlog.Info("SamWaf has started successfully.")
		zlog.Info("Security Entry Path Enabled! Your access code is: " + global.GWAF_SECURITY_ENTRY_PATH)
		zlog.Info("Access URL: http://127.0.0.1:" + strconv.Itoa(global.GWAF_LOCAL_SERVER_PORT) + "/" + global.GWAF_SECURITY_ENTRY_PATH + "/")
	} else {
		zlog.Info("SamWaf has started successfully.You can open http://127.0.0.1:" + strconv.Itoa(global.GWAF_LOCAL_SERVER_PORT) + " in your Browser")
	}
	for {
		select {
		case msg := <-global.GWAF_CHAN_MSG:
			if _, _hostExists := globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.GetHostByCode(msg.HostCode); _hostExists {
				switch msg.Type {
				case enums.ChanTypeAllowIP:
					ipWhiteLists := msg.Content.([]model.IPAllowList)
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.UpdateHost(msg.HostCode, func(h *wafenginmodel.HostSafe) { h.IPWhiteLists = ipWhiteLists })
					zlog.Debug("远程配置", zap.Any("IPWhiteLists", ipWhiteLists))
					break
				case enums.ChanTypeAllowURL:
					urlWhiteLists := msg.Content.([]model.URLAllowList)
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.UpdateHost(msg.HostCode, func(h *wafenginmodel.HostSafe) { h.UrlWhiteLists = urlWhiteLists })
					zlog.Debug("远程配置", zap.Any("UrlWhiteLists", urlWhiteLists))
					break
				case enums.ChanTypeBlockIP:
					ipBlockLists := msg.Content.([]model.IPBlockList)
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.UpdateHost(msg.HostCode, func(h *wafenginmodel.HostSafe) { h.IPBlockLists = ipBlockLists })
					zlog.Debug("远程配置", zap.Any("IPBlockLists", msg))
					break
				case enums.ChanTypeBlockURL:
					urlBlockLists := msg.Content.([]model.URLBlockList)
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.UpdateHost(msg.HostCode, func(h *wafenginmodel.HostSafe) { h.UrlBlockLists = urlBlockLists })
					zlog.Debug("远程配置", zap.Any("UrlBlockLists", urlBlockLists))
					break
				case enums.ChanTypeLdp:
					ldpUrlLists := msg.Content.([]model.LDPUrl)
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.UpdateHost(msg.HostCode, func(h *wafenginmodel.HostSafe) { h.LdpUrlLists = ldpUrlLists })
					zlog.Debug("远程配置", zap.Any("LdpUrlLists", ldpUrlLists))
					break
				case enums.ChanTypeRule:
					rules := msg.Content.([]model.Rules)
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.UpdateHostRules(msg.HostCode, rules)
					zlog.Debug("远程配置", zap.Any("Rule", rules))
					break
				case enums.ChanTypeAnticc:
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.ApplyAntiCCConfig(msg.HostCode, msg.Content.(model.AntiCC))
					break
				case enums.ChanTypeHttpauth:
					httpAuthBases := msg.Content.([]model.HttpAuthBase)
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.UpdateHost(msg.HostCode, func(h *wafenginmodel.HostSafe) { h.HttpAuthBases = httpAuthBases })
					zlog.Debug("远程配置", zap.Any("Http Auth", httpAuthBases))
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
								//情况2：同域名同主端口，重新加载数据
								// LoadHost 已做"原子替换"(单次发布，先清旧 key 再装新 key)，主端口 key 不会短暂缺失，
								// 故不再先 RemoveHost(会发布一张缺该 host 的快照→重载期间 403)。
								zlog.Debug("主机处理情况2 端口不变,域名也不变，就是重新加载数据")
								//清空已建代理，下次请求按新后端懒重建(LoadBalanceRuntime 自身 Mux 保护)
								globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.ResetHostProxiesByKey(hosts[0].Host + ":" + strconv.Itoa(hosts[0].Port))
								globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.LoadHost(hosts[0])
								globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.StartAllProxyServer()
								//副端口可能被删除：关闭已无主机占用的端口(在新路由发布后做，不影响主端口)
								globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.RemovePortServer()
							} else if hosts[0].Host == hostsOld.Host && hosts[0].Port != hostsOld.Port {
								//情况3：主端口从 A 切到 B。LoadHost 原子替换会清掉旧端口 key 并装上新端口 key。
								zlog.Debug("主机处理情况3 端口从A切换到B了，域名是旧的 ；端口更改后当前这个端口下没有域名了，应该是关闭了，并移除数据")
								globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.ResetHostProxiesByKey(hostsOld.Host + ":" + strconv.Itoa(hostsOld.Port))
								globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.LoadHost(hosts[0])
								globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.StartAllProxyServer()
								//旧端口 A 现已无主机占用：关闭其监听
								globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.RemovePortServer()
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
				case enums.ChanTypeLoadBalance:
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.ClearProxy(msg.HostCode)
					break
				case enums.ChanTypeSSL:
					host := msg.Content.(model.Hosts)
					zlog.Info(fmt.Sprintf("服务端准备为 %s 主机刷新 SSL证书 ，证书信息：%v", host.Host, utils.PrintSSLCert(host.Certfile)))
					// LoadHost 原子替换(单次发布)：刷新证书重载期间主端口 key 不缺失，不再先 RemoveHost(避免 403 空档)
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.LoadHost(host)
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.StartAllProxyServer()
					break
				case enums.ChanTypeBlockingPage:
					blockingPage := msg.Content.(map[string]model.BlockingPage)
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.UpdateHost(msg.HostCode, func(h *wafenginmodel.HostSafe) { h.BlockingPage = blockingPage })
					zlog.Debug("远程配置", zap.Any("配置自定义拦截界面信息", blockingPage))
					break
				case enums.ChanTypeCacheRule:
					cacheRule := msg.Content.([]model.CacheRule)
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.UpdateHost(msg.HostCode, func(h *wafenginmodel.HostSafe) { h.CacheRule = cacheRule })
					zlog.Debug("远程配置", zap.Any("配置缓存规则", cacheRule))
					break
				case enums.ChanTypeHostPathRule:
					pathRules := msg.Content.([]model.HostPathRule)
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.UpdateHost(msg.HostCode, func(h *wafenginmodel.HostSafe) { h.PathRules = pathRules })
					zlog.Debug("远程配置", zap.Any("配置路径路由规则", pathRules))
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
						for _, runTime := range hostRunTimeBean {
							globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.StartProxyServer(runTime)
						}
					}
					break
				}
			}
			break
		case common := <-global.GWAF_CHAN_COMMON_MSG:
			if common.Type == enums.ChanComTypeTunnel {
				//隧道类型
				switch common.OpType {
				case enums.OP_TYPE_NEW:
					tunnelNew := common.Content.(model.Tunnel)
					netRunTimes := globalobj.GWAF_RUNTIME_OBJ_TUNNEL_ENGINE.LoadTunnel(tunnelNew)
					for _, netRunTime := range netRunTimes {
						globalobj.GWAF_RUNTIME_OBJ_TUNNEL_ENGINE.StartTunnelServer(netRunTime)
					}
					break
				case enums.OP_TYPE_UPDATE:
					// 获取修改前的隧道信息
					tunnelOld := common.OldContent.(model.Tunnel)
					// 获取修改后的隧道信息
					tunnelNew := common.Content.(model.Tunnel)
					netRunTimes := globalobj.GWAF_RUNTIME_OBJ_TUNNEL_ENGINE.EditTunnel(tunnelOld, tunnelNew)
					for _, netRunTime := range netRunTimes {
						globalobj.GWAF_RUNTIME_OBJ_TUNNEL_ENGINE.StartTunnelServer(netRunTime)
					}
					break
				case enums.OP_TYPE_DELETE:
					tunnelDelete := common.OldContent.(model.Tunnel)
					globalobj.GWAF_RUNTIME_OBJ_TUNNEL_ENGINE.RemoveTunnel(tunnelDelete)
					break
				}
			} else if common.Type == enums.ChanComTypeApp {
				// 应用管理类型
				if globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE != nil {
					switch common.OpType {
					case enums.OP_TYPE_NEW:
						// 新增：如果 AutoStart=1，则启动
						appNew := common.Content.(model.WafApp)
						if appNew.AutoStart == 1 && appNew.StartStatus == 1 {
							if err := globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE.StartApp(appNew.Code); err != nil {
								zlog.Error("自动启动应用失败", "code", appNew.Code, "error", err.Error())
							}
						}
					case enums.OP_TYPE_UPDATE:
						appNew := common.Content.(model.WafApp)
						globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE.LoadApp(appNew)
					case enums.OP_TYPE_DELETE:
						appDel := common.OldContent.(model.WafApp)
						// 先停止进程（能读到 DB 中的 StopMode/StopCmd/StopTimeout 配置），再删 DB 记录
						globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE.RemoveApp(appDel.Code)
						global.GWAF_LOCAL_DB.Where("id = ?", appDel.Id).Delete(&model.WafApp{})
					case enums.OP_TYPE_APP_START:
						code := common.Content.(string)
						if err := globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE.StartApp(code); err != nil {
							zlog.Error("启动应用失败", "code", code, "error", err.Error())
						}
					case enums.OP_TYPE_APP_STOP:
						code := common.Content.(string)
						if err := globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE.StopApp(code); err != nil {
							zlog.Error("停止应用失败", "code", code, "error", err.Error())
						}
					case enums.OP_TYPE_APP_RESTART:
						code := common.Content.(string)
						if err := globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE.RestartApp(code); err != nil {
							zlog.Error("重启应用失败", "code", code, "error", err.Error())
						}
					}
				}
			}
		case engineStatus := <-global.GWAF_CHAN_ENGINE:
			if engineStatus == 1 {
				// 零空档重载：不再 CloseWaf(关监听器→connection refused 空档)+StartWaf，
				// 改为逐 host 原子替换 + 端口差分，业务监听 socket 全程不下线。
				zlog.Info("准备零空档重载WAF引擎")
				globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.ReloadAllHostZeroGap()

				// 隧道引擎为独立特性，仍按原逻辑重启（与 HTTP 业务端口无关）
				zlog.Info("准备关闭隧道引擎")
				globalobj.GWAF_RUNTIME_OBJ_TUNNEL_ENGINE.CloseTunnel()
				zlog.Info("准备启动隧道引擎")
				globalobj.GWAF_RUNTIME_OBJ_TUNNEL_ENGINE.StartTunnel()

			}
			break
		case host := <-global.GWAF_CHAN_HOST:
			// 防护开关热更新(copy-on-write，按 host:port key 定位)
			globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.UpdateHostByKey(host.Host+":"+strconv.Itoa(host.Port), func(h *wafenginmodel.HostSafe) {
				h.Host.GUARD_STATUS = host.GUARD_STATUS
			})
			zlog.Debug("规则", zap.Any("主机", host))
			break
		case update := <-global.GWAF_CHAN_UPDATE:
			if update == 1 {
				// 优雅升级：二进制已被 selfupdate 替换到磁盘。
				// 在 Supervisor 模式下，请求 Supervisor 编排滚动升级（起新 Worker→就绪→本 Worker 排空退出），
				// 本进程不自行退出，等待 Supervisor 下发 DRAIN，从而实现业务零中断。
				if gWorkerCtrl != nil {
					zlog.Info("[Worker] 二进制已就绪，请求 Supervisor 发起滚动升级（业务不中断）")
					gWorkerCtrl.RequestUpgrade()
					break
				}
				// 兜底：非 Supervisor 托管的独立运行模式，沿用原“停止→拉起新进程→退出”的硬重启。
				global.GWAF_RUNTIME_SERVER_TYPE = !service.Interactive()
				//需要重新启动
				if global.GWAF_RUNTIME_SERVER_TYPE == true {
					zlog.Info("服务形式重启")
					m.stopSamWaf()

					// 只启动一次新进程
					cmd := exec.Command(global.GWAF_RUNTIME_CURRENT_EXEPATH, "restart")
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stderr
					if err := cmd.Start(); err != nil {
						zlog.Error("启动新进程失败:", err)
						os.Exit(0)
					}
					time.Sleep(2 * time.Second)
					os.Exit(0)
				} else {
					m.stopSamWaf()
					cmd := exec.Command(global.GWAF_RUNTIME_CURRENT_EXEPATH)
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stderr
					if err := cmd.Start(); err != nil {
						zlog.Error("启动新进程失败:", err)
						os.Exit(0)
					}
					time.Sleep(2 * time.Second)
					os.Exit(0)
				}
			}
			break

		case sensitive := <-global.GWAF_CHAN_SENSITIVE:
			zlog.Debug("远程配置", sensitive)
			globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.ReLoadSensitive()
			break
		case sslOrderChan := <-global.GWAF_CHAN_SSLOrder:
			zlog.Debug("ssl证书申请", sslOrderChan)
			globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.ApplySSLOrder(sslOrderChan.Type, sslOrderChan.Content.(model.SslOrder))
			break
		case sslExpireCheck := <-global.GWAF_CHAN_SSL_EXPIRE_CHECK:
			zlog.Debug("ssl证书到期检测", sslExpireCheck)
			waftask.SSLExpireCheck()
			break
		case syncHostToSslExpire := <-global.GWAF_CHAN_SYNC_HOST_TO_SSL_EXPIRE:
			zlog.Debug("同步已存在主机到SSL证书检测任务里", syncHostToSslExpire)
			waftask.SyncHostToSslCheck()
			break
		case taskMethod := <-global.GWAF_CHAN_TASK:
			zlog.Debug("需要执行的方法", taskMethod)
			globalobj.GWAF_RUNTIME_OBJ_WAF_TaskScheduler.RunManual(taskMethod)
			break
		case taskReload := <-global.GWAF_CHAN_TASK_RELOAD:
			zlog.Info("任务重新加载", "taskName", taskReload.TaskName, "taskMethod", taskReload.TaskMethod)
			err := globalobj.GWAF_RUNTIME_OBJ_WAF_TaskScheduler.RescheduleTask(
				taskReload.TaskUnit,
				taskReload.TaskValue,
				taskReload.TaskAt,
				taskReload.TaskMethod,
				taskReload.TaskDaysOfTheWeek,
			)
			if err != nil {
				zlog.Error("任务重新加载失败", "error", err.Error(), "taskName", taskReload.TaskName)
			} else {
				zlog.Info("任务重新加载成功", "taskName", taskReload.TaskName)
			}
			break
		case clearCcWindows := <-global.GWAF_CHAN_CLEAR_CC_WINDOWS:
			zlog.Debug("定时清空CCwindows", clearCcWindows)
			globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.ClearCcWindows()
			break
		case clearCcWindowsIp := <-global.GWAF_CHAN_CLEAR_CC_IP:
			zlog.Debug("定时清空CCip", clearCcWindowsIp)
			globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.ClearCcWindowsForIP(clearCcWindowsIp)
			break
		}

	}
	zlog.Info("normal program close")
}

// 停止要提前关闭的 是服务的主要逻辑
func (m *wafSystenService) stopSamWaf() {
	zlog.Info("Shutdown SamWaf Engine...")
	if globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE != nil {
		globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.CloseWaf()
		zlog.Info("Shutdown SamWaf Engine finished")
	} else {
		zlog.Warn("WAF Engine is nil, skipping shutdown")
	}

	zlog.Info("Shutdown SamWaf Tunnel Engine...")
	if globalobj.GWAF_RUNTIME_OBJ_TUNNEL_ENGINE != nil {
		globalobj.GWAF_RUNTIME_OBJ_TUNNEL_ENGINE.CloseTunnel()
		zlog.Info("Shutdown SamWaf Tunnel Engine finished")
	} else {
		zlog.Warn("Tunnel Engine is nil, skipping shutdown")
	}

	zlog.Info("Shutdown SamWaf App Engine...")
	if globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE != nil {
		globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE.StopApps()
		zlog.Info("Shutdown SamWaf App Engine finished")
	} else {
		zlog.Warn("App Engine is nil, skipping shutdown")
	}

	zlog.Info("Shutdown SamWaf Queue Processors...")
	// 关闭信号通道，通知所有队列处理协程退出
	close(global.GWAF_QUEUE_SHUTDOWN_SIGNAL)
	// 等待一段时间，让队列处理协程有时间完成当前工作并退出
	time.Sleep(500 * time.Millisecond)
	zlog.Info("Shutdown SamWaf Queue Processors finished")

	// 设置任务停止标志
	zlog.Info("Notifying SamWaf Tasks to shutdown...")
	global.GWAF_SHUTDOWN_SIGNAL = true
	// 给任务一些时间完成当前工作
	time.Sleep(200 * time.Millisecond)
	zlog.Info("SamWaf Tasks notified")

	zlog.Info("Shutdown SamWaf Cron...")
	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskScheduler.Stop()
	zlog.Info("Shutdown SamWaf Cron finished")

	zlog.Info("Shutdown SamWaf WebManager...")
	webmanager.Shutdown()
	zlog.Info("Shutdown SamWaf WebManager finished")

	zlog.Info("Shutdown SamWaf IPDatabase...")
	utils.CloseIPDatabase()
	zlog.Info("Shutdown SamWaf IPDatabase finished")

	// 关闭插件系统
	zlog.Info("Shutdown SamWaf Plugin System...")
	if globalobj.GWAF_RUNTIME_OBJ_PLUGIN_MANAGER != nil {
		if err := globalobj.GWAF_RUNTIME_OBJ_PLUGIN_MANAGER.Shutdown(); err != nil {
			zlog.Error("Shutdown Plugin System failed", zap.Error(err))
		} else {
			zlog.Info("Shutdown SamWaf Plugin System finished")
		}
	} else {
		zlog.Warn("Plugin Manager is nil, skipping shutdown")
	}

}

// supervisorService 是被服务管理器(kardianos)托管的“监护进程”程序。
// 它常驻、永不为升级而退出，负责拉起/监护/滚动升级 Worker 子进程。
type supervisorService struct {
	sup *supervisor.Supervisor
}

func (s *supervisorService) Start(svc service.Service) error {
	zlog.Info("[Supervisor] 服务启动")
	go func() {
		if err := s.sup.Run(); err != nil {
			zlog.Error("[Supervisor] 运行失败: " + err.Error())
		}
	}()
	return nil
}

func (s *supervisorService) Stop(svc service.Service) error {
	zlog.Info("[Supervisor] 服务停止")
	s.sup.Shutdown()
	return nil
}

// gracefulOnce 保证优雅停止只执行一次，无论由服务 Stop()、系统信号，
// 还是后续 Supervisor 的 DRAIN 指令触发。
var gracefulOnce sync.Once

// Graceful 优雅停止的统一入口：先排空业务连接(StopAllProxyServer 已支持 Shutdown 排空)，
// 回收各引擎/队列/任务资源，最后关闭数据库连接。供信号、服务 Stop 和升级 DRAIN 复用。
func (m *wafSystenService) Graceful() {
	gracefulOnce.Do(func() {
		zlog.Info("[Graceful] 开始优雅停止：排空业务连接并回收资源 ...")
		m.stopSamWaf()           // 内部 CloseWaf→StopAllProxyServer 已优雅排空在途连接
		wafsafeclear.SafeClear() // 最后关闭数据库连接
		zlog.Info("[Graceful] 优雅停止完成")
	})
}

// @title           SamWaf Open API
// @version         1.0
// @description     SamWaf Web Application Firewall 开放平台 API 文档。需要在请求头携带 X-API-Key 进行鉴权。
// @BasePath        /api/v1
// @securityDefinitions.apikey ApiKeyAuth
// @in              header
// @name            X-API-Key
func main() {
	fmt.Println(`
==========================================
  SamWaf Web Application Firewall ` + global.GWAF_RELEASE_VERSION + `
  Version Name: ` + global.GWAF_RELEASE_VERSION_NAME + ` 
==========================================
`)
	//加载配置
	wafconfig.LoadAndInitConfig()
	// 多进程日志隔离：Supervisor 与 Worker 是同一二进制的两个进程，若都写同一个 logs/log.log，
	// lumberjack 滚动时 rename 会因文件被另一进程占用而失败(Windows)，导致日志再也滚不动。
	// 故 Supervisor 角色单独写 supervisor.log；Worker 仍写 log.log（主业务日志名不变）。
	// parseWorkerRole 仅扫描 os.Args，不依赖日志/配置，可安全前置调用。
	if isWorker, _, _, _ := parseWorkerRole(); !isWorker {
		zlog.FileName = "supervisor.log"
	}
	//初始化日志
	zlog.InitZLog(global.GWAF_LOG_DEBUG_ENABLE, global.GWAF_LOG_OUTPUT_FORMAT)
	if v := recover(); v != nil {
		zlog.Error("主流程上被异常了")
	}
	pid := os.Getpid()
	zlog.Debug("SamWaf Current PID:" + strconv.Itoa(pid))

	// 调试标识：响应头标记处理进程，便于验证升级时新旧 Worker 交替。
	// 主开关在 config.yml 的 debug_worker_header（已由上方 LoadAndInitConfig 读入，Supervisor/Worker 均生效，
	// 服务模式下务必用配置项——SCM/systemd 不会传入交互式 shell 的环境变量）。
	// 环境变量 SAMWAF_WORKER_HEADER=1 仅作前台调试的临时叠加开关（只会打开、不会关闭配置已开的开关）。
	global.GWAF_WORKER_TAG = "pid=" + strconv.Itoa(pid) + " born=" + time.Now().Format("15:04:05")
	if os.Getenv("SAMWAF_WORKER_HEADER") == "1" {
		global.GWAF_DEBUG_WORKER_HEADER = true
	}

	// 角色分流：带 --worker 的进程由 Supervisor 拉起，直接运行业务引擎 + 控制通道客户端。
	if workerRole, ctrlAddr, ctrlToken, takeover := parseWorkerRole(); workerRole {
		global.GWAF_RUNTIME_IS_TAKEOVER = takeover
		//获取外网IP
		global.GWAF_RUNTIME_IP = utils.GetExternalIp()
		wp := &wafSystenService{}
		if ctrlAddr != "" {
			startWorkerControl(ctrlAddr, ctrlToken, wp)
		}
		// Worker 自身的信号处理：收到中断/终止(如前台 Ctrl+C、systemd SIGTERM)时优雅排空再退出。
		// 与 Supervisor 下发的 DRAIN/SHUTDOWN 经 gracefulOnce 去重，只执行一次。
		go func() {
			sc := make(chan os.Signal, 1)
			signal.Notify(sc, os.Interrupt, syscall.SIGTERM)
			s := <-sc
			zlog.Info("[Worker] 收到系统信号优雅停止: " + s.String())
			wp.Graceful()
			os.Exit(0)
		}()
		zlog.Info("以 Worker 角色启动 (takeover=" + strconv.FormatBool(takeover) + ")")
		wp.run() // 阻塞运行引擎事件循环
		return
	}
	// ===== 以下为 Supervisor 角色（默认，被服务管理器托管，常驻不为升级退出）=====

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
	exePath, _ := os.Executable()
	dataDir := filepath.Join(utils.GetCurrentDir(), "data")
	sup := supervisor.New(supervisor.Options{
		ExePath:      exePath,
		DataDir:      dataDir,
		DrainTimeout: int(global.GCONFIG_RECORD_DRAIN_TIMEOUT),
	})
	prg := &supervisorService{sup: sup}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatal(err)
	}

	// 设置服务控制信号处理程序：收到中断/终止信号时，令 Supervisor 通知各 Worker 优雅退出再停止。
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, os.Kill, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		zlog.Info("收到系统信号，Supervisor 开始优雅停止: " + sig.String())
		sup.Shutdown()
		os.Exit(0)
	}()

	if len(os.Args) > 1 {
		command := os.Args[1]
		switch command {

		case "install", "start", "stop", "uninstall", "restart": // 以服务方式运行
			err := service.Control(s, command)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("Samwaf has successfully executed the '%s' command.\n", command)
			break
		case "rolling-restart": // 零停机滚动重启：通知运行中的 Supervisor 换 Worker（业务不中断），亦用于测试升级编排
			if err := supervisor.TriggerUpgrade(dataDir); err != nil {
				fmt.Println("滚动重启触发失败:", err)
				os.Exit(1)
			}
			fmt.Println("已触发零停机滚动重启，请观察日志：新 Worker 就绪后旧 Worker 将优雅排空退出。")
		case "resetpwd": //重制密码
			wafdb.InitCoreDb("")
			wafdb.ResetAdminPwd()
		case "resetotp": //重置安全码
			wafdb.InitCoreDb("")
			wafdb.ResetAdminOTP()
		case "repairdb": //修复数据库
			fmt.Println("\n⚠️  数据库修复工具")
			fmt.Println("如果您遇到数据库损坏错误")
			fmt.Println("可以使用此工具尝试修复。\n")
			wafdb.RepairAllDatabases("")
		case "execsql": //执行SQL语句
			fmt.Println("\n💻 SQL 执行工具")
			fmt.Println("可以在指定数据库上执行 SQL 语句\n")
			wafdb.ExecuteSQLCommand("")
		case "migratedb": // 离线迁移：SQLite → MySQL
			opts := wafdb.MigrateOptions{}
			for _, arg := range os.Args[2:] {
				switch arg {
				case "--dry-run":
					opts.DryRun = true
				case "--force":
					opts.Force = true
				}
			}
			if err := wafdb.RunMigrateDB(opts); err != nil {
				fmt.Println("迁移失败:", err)
				os.Exit(1)
			}
		case "rollback": //版本回退
			fmt.Println("================================================")
			fmt.Println("         SamWaf 版本回退工具")
			fmt.Println("================================================")
			fmt.Printf("当前运行版本: %s\n\n", global.GWAF_RELEASE_VERSION)

			list, err := wafupdate.ListBackups()
			if err != nil {
				fmt.Println("获取备份列表失败:", err)
				return
			}
			if len(list) == 0 {
				fmt.Println("没有可用的备份版本，无法回退")
				return
			}

			fmt.Printf("%-4s %-15s %-22s %-10s %s\n", "序号", "版本", "备份时间", "大小(MB)", "备注")
			fmt.Println("------------------------------------------------------------------------")
			for i, b := range list {
				note := ""
				if b.Version == global.GWAF_RELEASE_VERSION {
					note = "[当前版本]"
				}
				fmt.Printf("%-4d %-15s %-22s %-10.2f %s\n",
					i+1,
					b.Version,
					b.BackupTime.Format("2006-01-02 15:04:05"),
					float64(b.FileSize)/(1024*1024),
					note)
			}
			fmt.Println("------------------------------------------------------------------------")

			fmt.Print("\n请输入要回退的序号，或输入 'q' 退出: ")
			var input string
			fmt.Scanln(&input)
			if input == "q" || input == "Q" {
				fmt.Println("已退出版本回退工具")
				return
			}

			idx := 0
			_, parseErr := fmt.Sscanf(input, "%d", &idx)
			if parseErr != nil || idx < 1 || idx > len(list) {
				fmt.Printf("无效的序号: %s\n", input)
				return
			}

			target := list[idx-1]
			if target.Version == global.GWAF_RELEASE_VERSION {
				fmt.Printf("所选版本 %s 与当前运行版本相同，无需回退\n", target.Version)
				return
			}

			fmt.Printf("\n即将回退到: %s（%s）\n", target.Version, target.BackupTime.Format("2006-01-02 15:04:05"))
			fmt.Print("确认回退？回退后需要手动重启服务 (y/n): ")
			var confirm string
			fmt.Scanln(&confirm)
			if confirm != "y" && confirm != "Y" {
				fmt.Println("已取消")
				return
			}

			fmt.Printf("正在回退到版本 %s...\n", target.Version)
			if rollbackErr := wafupdate.RollbackExecutable(target.Version); rollbackErr != nil {
				fmt.Println("回退失败:", rollbackErr)
				return
			}
			fmt.Println("回退成功，请重启服务 (samwaf start 或 samwaf restart)")
		default:
			fmt.Printf("Command '%s' is not recognized.\n", command)
			fmt.Println("\n可用命令:")
			fmt.Println("  install   - 安装为系统服务")
			fmt.Println("  start     - 启动服务")
			fmt.Println("  stop      - 停止服务")
			fmt.Println("  restart   - 重启服务")
			fmt.Println("  rolling-restart - 零停机滚动重启(换 Worker，业务不中断)")
			fmt.Println("  uninstall - 卸载服务")
			fmt.Println("  resetpwd  - 重置管理员密码")
			fmt.Println("  resetotp  - 重置安全码")
			fmt.Println("  repairdb  - 修复损坏的数据库")
			fmt.Println("  execsql   - 执行SQL语句（支持SELECT/UPDATE/DELETE等）")
			fmt.Println("  migratedb - 离线迁移数据库（SQLite → MySQL，需先在 config.yml 设 driver: mysql）")
			fmt.Println("              --dry-run  只做预估，不写入数据")
			fmt.Println("              --force    目标表已有数据时强制覆盖")
			fmt.Println("  rollback  - 回退到历史版本 (--list 列出, --version=v1.x.x 指定版本)")
			fmt.Println("")
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
	// 以常规方式运行
	err = s.Run()
	if err != nil {
		log.Fatal(err)
	}

}

// ===== 优雅升级 Worker 侧控制通道客户端（与 Supervisor 通信） =====

// parseWorkerRole 解析进程角色与控制参数。
// 由 Supervisor 拉起的 Worker 会带 --worker --ctrl-addr=127.0.0.1:port --token=xxx [--takeover]。
func parseWorkerRole() (worker bool, ctrlAddr, token string, takeover bool) {
	for _, a := range os.Args[1:] {
		switch {
		case a == "--worker":
			worker = true
		case a == "--takeover":
			takeover = true
		case strings.HasPrefix(a, "--ctrl-addr="):
			ctrlAddr = strings.TrimPrefix(a, "--ctrl-addr=")
		case strings.HasPrefix(a, "--token="):
			token = strings.TrimPrefix(a, "--token=")
		}
	}
	return
}

// workerCtrl 是 Worker 侧的控制通道客户端：连接 Supervisor、上报 HELLO/READY/HEARTBEAT、
// 响应 DRAIN/SHUTDOWN/PING；断线自动重连（支撑 Supervisor 自升级后的“再认领”）。
type workerCtrl struct {
	addr  string
	token string
	prg   *wafSystenService

	mu   sync.Mutex
	conn *wafipc.Conn
	down bool
}

// gWorkerCtrl 当前进程的 Worker 控制客户端（仅 worker 角色下非 nil）。
var gWorkerCtrl *workerCtrl

// activateOnce 保证独占单例(应用/隧道/cron)只被接管启动一次。
var activateOnce sync.Once

// activateSingletons 启动独占型单例：隧道、应用、cron 任务调度。
// takeover 升级模式下由 Supervisor 在旧 Worker 退出后经 ACTIVATE 触发（此时旧 Worker 已释放这些资源，避免端口/进程冲突）；
// 非 takeover（首次启动/自愈重拉）则在 run() 内联启动，不经过这里。
func activateSingletons() {
	activateOnce.Do(func() {
		zlog.Info("[Worker] 接管独占单例：启动隧道 / 应用 / 任务调度")
		if globalobj.GWAF_RUNTIME_OBJ_TUNNEL_ENGINE != nil {
			globalobj.GWAF_RUNTIME_OBJ_TUNNEL_ENGINE.StartTunnel()
		}
		if globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE != nil {
			globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE.StartApps()
		}
		if globalobj.GWAF_RUNTIME_OBJ_WAF_TaskScheduler != nil {
			globalobj.GWAF_RUNTIME_OBJ_WAF_TaskScheduler.Start()
		}
	})
}

// startWorkerControl 启动 Worker 控制通道客户端（后台重连循环）。
func startWorkerControl(addr, token string, prg *wafSystenService) {
	gWorkerCtrl = &workerCtrl{addr: addr, token: token, prg: prg}
	go gWorkerCtrl.loop()
}

func (wc *workerCtrl) loop() {
	for {
		if wc.isDown() {
			return
		}
		conn, err := wafipc.Dial(wc.addr)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		wc.setConn(conn)
		wc.send(wafipc.Message{
			Type:     wafipc.MsgHello,
			PID:      os.Getpid(),
			Version:  global.GWAF_RELEASE_VERSION,
			ProtoVer: wafipc.ProtoVersion,
			Token:    wc.token,
		})
		wc.serve(conn) // 阻塞直到连接出错
		conn.Close()
		wc.setConn(nil)
		if wc.isDown() {
			return
		}
		time.Sleep(2 * time.Second) // 重连
	}
}

func (wc *workerCtrl) serve(conn *wafipc.Conn) {
	stop := make(chan struct{})
	defer close(stop)

	// 就绪上报：等引擎端口起来后发 READY
	go func() {
		for i := 0; i < 600; i++ { // 最多约 60s 等引擎对象建立
			if globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE != nil {
				break
			}
			select {
			case <-stop:
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
		if globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE != nil {
			_ = globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.WaitProxyReady(60 * time.Second)
		}
		wc.send(wafipc.Message{Type: wafipc.MsgReady, PID: os.Getpid()})
	}()

	// 心跳：上报当前连接数
	go func() {
		t := time.NewTicker(3 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				var conns int64
				if globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE != nil {
					conns = globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.TotalConns()
				}
				wc.send(wafipc.Message{Type: wafipc.MsgHeartbeat, PID: os.Getpid(), Active: conns})
			}
		}
	}()

	// 命令读取
	for {
		m, err := conn.Recv()
		if err != nil {
			return
		}
		switch m.Type {
		case wafipc.MsgDrain, wafipc.MsgShutdown:
			zlog.Info("[Worker] 收到 " + m.Type + " 指令，开始优雅排空退出")
			go wc.gracefulExit()
			return
		case wafipc.MsgActivate:
			zlog.Info("[Worker] 收到 ACTIVATE 指令，接管独占单例(应用/隧道/任务调度)")
			go activateSingletons()
		case wafipc.MsgPing:
			wc.send(wafipc.Message{Type: wafipc.MsgPong, PID: os.Getpid()})
		}
	}
}

func (wc *workerCtrl) gracefulExit() {
	wc.markDown()
	wc.prg.Graceful()
	wc.send(wafipc.Message{Type: wafipc.MsgGone, PID: os.Getpid()})
	time.Sleep(200 * time.Millisecond)
	os.Exit(0)
}

// RequestUpgrade 通知 Supervisor 发起滚动升级（二进制已被 selfupdate 替换到磁盘）。
func (wc *workerCtrl) RequestUpgrade() {
	wc.send(wafipc.Message{Type: wafipc.MsgRequestUpgrade, PID: os.Getpid()})
}

func (wc *workerCtrl) send(m wafipc.Message) {
	wc.mu.Lock()
	defer wc.mu.Unlock()
	if wc.conn != nil {
		_ = wc.conn.Send(m)
	}
}

func (wc *workerCtrl) setConn(c *wafipc.Conn) {
	wc.mu.Lock()
	wc.conn = c
	wc.mu.Unlock()
}

func (wc *workerCtrl) isDown() bool {
	wc.mu.Lock()
	defer wc.mu.Unlock()
	return wc.down
}

func (wc *workerCtrl) markDown() {
	wc.mu.Lock()
	wc.down = true
	wc.mu.Unlock()
}
