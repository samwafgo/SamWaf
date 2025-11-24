package main

import (
	"SamWaf/cache"
	"SamWaf/common/gwebsocket"
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/globalobj"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/utils"
	"SamWaf/wafconfig"
	"SamWaf/wafdb"
	"SamWaf/wafenginecore"
	"SamWaf/wafenginecore/wafcaptcha"
	"SamWaf/wafinit"
	"SamWaf/wafipban"
	"SamWaf/wafmangeweb"
	"SamWaf/wafnotify"
	"SamWaf/wafowasp"
	"SamWaf/wafqueue"
	"SamWaf/wafreg"
	"SamWaf/wafsafeclear"
	"SamWaf/wafsnowflake"
	"SamWaf/waftask"
	"SamWaf/waftunnelengine"
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

	// 先尝试监听端口，检查是否被占用
	listener, err := net.Listen("tcp", ":"+strconv.Itoa(global.GWAF_LOCAL_SERVER_PORT))
	defer func() {
		if listener != nil {
			err := listener.Close()
			if err != nil {
				return
			}
		}
	}()
	if err != nil {
		errMsg := fmt.Sprintf("管理界面端口 %d 已被占用，请检查并修改配置(conf/config.yml local_port字段)或关闭占用该端口的程序: %s",
			global.GWAF_LOCAL_SERVER_PORT, err.Error())
		zlog.Error(errMsg)
		panic(errMsg)
		return
	}
	if listener != nil {
		listener.Close()
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
	// 从嵌入的文件中读取内容

	// 拼接文件路径
	ip2RegionFilePath := filepath.Join(utils.GetCurrentDir(), "data", "ip2region.xdb")
	// 检查文件是否存在
	if _, err := os.Stat(ip2RegionFilePath); os.IsNotExist(err) {
		global.GCACHE_IP_CBUFF = Ip2regionBytes
	} else {
		// 读取文件内容
		fileBytes, err := ioutil.ReadFile(ip2RegionFilePath)
		if err != nil {
			log.Fatalf("Failed to read IP database file ip2region.xdb: %v", err)
		}
		global.GCACHE_IP_CBUFF = fileBytes
		// 检查是否成功读取
		zlog.Info("IP database ip2region.xdb loaded into cache, size: ", len(global.GCACHE_IP_CBUFF), ip2RegionFilePath)
	}

	//检测是否存在IPV6得数据包
	ipv6RegionFilePath := filepath.Join(utils.GetCurrentDir(), "data", "GeoLite2-Country.mmdb")
	// 检查文件是否存在
	if _, err := os.Stat(ipv6RegionFilePath); os.IsNotExist(err) {
		global.GCACHE_IP_V6_COUNTRY_CBUFF = Ipv6CountryBytes
	} else {
		// 读取文件内容
		fileBytes, err := ioutil.ReadFile(ipv6RegionFilePath)
		if err != nil {
			log.Fatalf("Failed to read IPv6 database file GeoLite2-Country.mmdb: %v", err)
		}
		global.GCACHE_IP_V6_COUNTRY_CBUFF = fileBytes
		// 检查是否成功读取
		zlog.Info("IPv6 database file GeoLite2-Country.mmdb loaded into cache, size: ", len(global.GCACHE_IP_V6_COUNTRY_CBUFF), ipv6RegionFilePath)
	}
	global.GWAF_DLP_CONFIG = ldpConfig
	global.GWAF_REG_PUBLIC_KEY = publicKey

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
	//TODO 准备释放最新spider bot

	//初始化cache
	global.GCACHE_WAFCACHE = cache.InitWafCache()
	//初始化验证码服务
	wafcaptcha.InitCaptchaService(global.GCACHE_WAFCACHE)
	//初始化锁写不锁度
	global.GWAF_MEASURE_PROCESS_DEQUEENGINE = cache.InitWafOnlyLockWrite()
	// 创建 Snowflake 实例
	global.GWAF_SNOWFLAKE_GEN = wafsnowflake.NewSnowflake(1609459200000, 1, 1) // 设置epoch时间、机器ID和数据中心ID

	// 创建owasp
	global.GWAF_OWASP = wafowasp.NewWafOWASP(true, utils.GetCurrentDir())

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
	isNewMainDb, err := wafdb.InitCoreDb("")
	if err == nil {
		if isNewMainDb {
			waftask.TaskCreateIndexByDbName(enums.DB_MAIN)
		}
	}
	isNewLogDb, err := wafdb.InitLogDb("")
	if err == nil {
		if isNewLogDb {
			waftask.TaskCreateIndexByDbName(enums.DB_LOG)
		}
	}
	isNewStatsDb, err := wafdb.InitStatsDb("")
	if err == nil {
		if isNewStatsDb {
			waftask.TaskCreateIndexByDbName(enums.DB_STATS)
		}
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
	//启动通知相关程序
	global.GNOTIFY_KAKFA_SERVICE = wafnotify.InitNotifyKafkaEngine(global.GCONFIG_RECORD_KAFKA_ENABLE, global.GCONFIG_RECORD_KAFKA_URL, global.GCONFIG_RECORD_KAFKA_TOPIC) //kafka
	//启动waf
	globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE = &wafenginecore.WafEngine{
		HostTarget: map[string]*wafenginmodel.HostSafe{},
		//主机和code的关系
		HostCode:             map[string]string{},
		HostTargetNoPort:     map[string]string{},
		HostTargetMoreDomain: map[string]string{},
		ServerOnline:         wafenginmodel.NewSafeServerMap(),
		//所有证书情况 对应端口 可能多个端口都是https 443，或者其他非标准端口也要实现https证书
		AllCertificate: wafenginecore.AllCertificate{
			Mux: sync.Mutex{},
			Map: map[string]*tls.Certificate{},
		},
		EngineCurrentStatus: 0, // 当前waf引擎状态
		Sensitive:           make([]model.Sensitive, 0),
	}
	http.Handle("/", globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE)
	globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.StartWaf()

	//启动隧道
	globalobj.GWAF_RUNTIME_OBJ_TUNNEL_ENGINE = waftunnelengine.NewWafTunnelEngine()
	globalobj.GWAF_RUNTIME_OBJ_TUNNEL_ENGINE.StartTunnel()
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
	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskRegistry.RegisterTask(enums.TASK_CREATE_DB_INDEX, waftask.TaskCreateIndex)
	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskRegistry.RegisterTask(enums.TASK_CLEAR_WEBCACHE, waftask.TaskClearWebcache)
	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskRegistry.RegisterTask(enums.TASK_GC, waftask.TaskGC)
	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskRegistry.RegisterTask(enums.TASK_STATS_PUSH, waftask.TaskStatsPush)
	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskRegistry.RegisterTask(enums.TASK_DB_MONITOR, waftask.TaskDatabaseMonitor)

	go waftask.TaskShareDbInfo()

	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskScheduler = waftask.NewTaskScheduler(globalobj.GWAF_RUNTIME_OBJ_WAF_TaskRegistry)
	taskDbList := waftask.InitTaskDb()
	for _, task := range taskDbList {
		globalobj.GWAF_RUNTIME_OBJ_WAF_TaskScheduler.ScheduleTask(task.TaskUnit, task.TaskValue, task.TaskAt, task.TaskMethod, task.TaskDaysOfTheWeek)
	}
	//结束 需要添加到任务注册器里面的
	globalobj.GWAF_RUNTIME_OBJ_WAF_TaskScheduler.Start()

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

	zlog.Info("SamWaf has started successfully.You can open http://127.0.0.1:" + strconv.Itoa(global.GWAF_LOCAL_SERVER_PORT) + " in your Browser")
	for {
		select {
		case msg := <-global.GWAF_CHAN_MSG:
			if globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]] != nil && globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode] != "" {
				switch msg.Type {
				case enums.ChanTypeAllowIP:
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].Mux.Lock()
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].IPWhiteLists = msg.Content.([]model.IPAllowList)
					zlog.Debug("远程配置", zap.Any("IPWhiteLists", msg.Content.([]model.IPAllowList)))
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].Mux.Unlock()
					break
				case enums.ChanTypeAllowURL:
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].Mux.Lock()
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].UrlWhiteLists = msg.Content.([]model.URLAllowList)
					zlog.Debug("远程配置", zap.Any("UrlWhiteLists", msg.Content.([]model.URLAllowList)))
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
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.ApplyAntiCCConfig(msg.HostCode, msg.Content.(model.AntiCC))
					break
				case enums.ChanTypeHttpauth:
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].Mux.Lock()
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].HttpAuthBases = msg.Content.([]model.HttpAuthBase)
					zlog.Debug("远程配置", zap.Any("Http Auth", msg.Content.([]model.HttpAuthBase)))
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
									len(globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[hosts[0].Host+":"+strconv.Itoa(hosts[0].Port)].LoadBalanceRuntime.RevProxies) > 0 {
									//设置空代理
									globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[hosts[0].Host+":"+strconv.Itoa(hosts[0].Port)].LoadBalanceRuntime.RevProxies = nil
									zlog.Debug("主机重新代理", hosts[0].Host+":"+strconv.Itoa(hosts[0].Port))
								}
								//如果本次是关闭，那么应该关闭主机
								if hosts[0].START_STATUS == 1 {
									globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.RemoveHost(hosts[0])
								}
								//如果本次ssl和上次ssl不同
								if hosts[0].Ssl != hostsOld.Ssl || hosts[0].Keyfile != hostsOld.Keyfile || hosts[0].Certfile != hostsOld.Certfile {
									globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.RemoveHost(hosts[0])
								}
								//绑定更多域名变更了
								if hosts[0].BindMoreHost != hostsOld.BindMoreHost {
									globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.RemoveHost(hosts[0])
								}
								// 远程 IP 或端口变化，需重载
								if hosts[0].Remote_ip != hostsOld.Remote_ip || hosts[0].Remote_port != hostsOld.Remote_port {
									globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.RemoveHost(hosts[0])
								}
								// 负载状态或策略变化，需重载
								if hosts[0].IsEnableLoadBalance != hostsOld.IsEnableLoadBalance || hosts[0].LoadBalanceStage != hostsOld.LoadBalanceStage {
									globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.RemoveHost(hosts[0])
								}
								globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.LoadHost(hosts[0])
								globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.StartAllProxyServer()
							} else if hosts[0].Host == hostsOld.Host && hosts[0].Port != hostsOld.Port {
								//情况3
								zlog.Debug("主机处理情况3 端口从A切换到B了，域名是旧的 ；端口更改后当前这个端口下没有域名了，应该是关闭了，并移除数据")
								if globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[hostsOld.Host+":"+strconv.Itoa(hostsOld.Port)] != nil &&
									len(globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[hostsOld.Host+":"+strconv.Itoa(hostsOld.Port)].LoadBalanceRuntime.RevProxies) > 0 {
									globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[hostsOld.Host+":"+strconv.Itoa(hostsOld.Port)].LoadBalanceRuntime.RevProxies = nil
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
				case enums.ChanTypeLoadBalance:
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.ClearProxy(msg.HostCode)
					break
				case enums.ChanTypeSSL:
					host := msg.Content.(model.Hosts)
					zlog.Info(fmt.Sprintf("服务端准备为 %s 主机刷新 SSL证书 ，证书信息：%v", host.Host, utils.PrintSSLCert(host.Certfile)))
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.RemoveHost(host)
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.LoadHost(host)
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.StartAllProxyServer()
					break
				case enums.ChanTypeBlockingPage:
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].Mux.Lock()
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].BlockingPage = msg.Content.(map[string]model.BlockingPage)
					zlog.Debug("远程配置", zap.Any("配置自定义拦截界面信息", msg.Content.(map[string]model.BlockingPage)))
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].Mux.Unlock()
					break
				case enums.ChanTypeCacheRule:
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].Mux.Lock()
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].CacheRule = msg.Content.([]model.CacheRule)
					zlog.Debug("远程配置", zap.Any("配置缓存规则", msg.Content.([]model.CacheRule)))
					globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostTarget[globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.HostCode[msg.HostCode]].Mux.Unlock()
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
			}
		case engineStatus := <-global.GWAF_CHAN_ENGINE:
			if engineStatus == 1 {
				zlog.Info("准备关闭WAF引擎")
				globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.CloseWaf()
				zlog.Info("准备启动WAF引擎")
				globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.StartWaf()

				zlog.Info("准备关闭隧道引擎")
				globalobj.GWAF_RUNTIME_OBJ_TUNNEL_ENGINE.CloseTunnel()
				zlog.Info("准备启动隧道引擎")
				globalobj.GWAF_RUNTIME_OBJ_TUNNEL_ENGINE.StartTunnel()

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
		case clearCcWindows := <-global.GWAF_CHAN_CLEAR_CC_WINDOWS:
			zlog.Debug("定时清空CCwindows", clearCcWindows)
			globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.ClearCcWindows()
			break
		case clearCcWindowsIp := <-global.GWAF_CHAN_CLEAR_CC_IP:
			zlog.Debug("定时清空CCip", clearCcWindowsIp)
			globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.ClearCcWindowsForIP(clearCcWindowsIp)
			break
		case createLogIndex := <-global.GWAF_CHAN_CREATE_LOG_INDEX:
			zlog.Debug("定时创建日志索引", createLogIndex)
			waftask.TaskCreateIndexByDbName(enums.DB_LOG)
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

}

// 优雅升级
func (m *wafSystenService) Graceful() {
	//https://github.com/pengge/uranus/blob/main/main.go 预备参考
}

func main() {
	fmt.Println(`
==========================================
  SamWaf Web Application Firewall ` + global.GWAF_RELEASE_VERSION + `
  Version Name: ` + global.GWAF_RELEASE_VERSION_NAME + ` 
==========================================
`)
	//加载配置
	wafconfig.LoadAndInitConfig()
	//初始化日志
	zlog.InitZLog(global.GWAF_LOG_DEBUG_ENABLE, global.GWAF_LOG_OUTPUT_FORMAT)
	if v := recover(); v != nil {
		zlog.Error("主流程上被异常了")
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
		default:
			fmt.Printf("Command '%s' is not recognized.\n", command)
			fmt.Println("\n可用命令:")
			fmt.Println("  install   - 安装为系统服务")
			fmt.Println("  start     - 启动服务")
			fmt.Println("  stop      - 停止服务")
			fmt.Println("  restart   - 重启服务")
			fmt.Println("  uninstall - 卸载服务")
			fmt.Println("  resetpwd  - 重置管理员密码")
			fmt.Println("  resetotp  - 重置安全码")
			fmt.Println("  repairdb  - 修复损坏的数据库")
			fmt.Println("  execsql   - 执行SQL语句（支持SELECT/UPDATE/DELETE等）")
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
