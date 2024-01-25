package globalobj

import (
	"SamWaf/wafenginecore"
	"github.com/go-co-op/gocron"
)

var (
	/***
	本地对象映射关系
	*/
	GWAF_RUNTIME_OBJ_WAF_ENGINE *wafenginecore.WafEngine //当前引擎对象
	GWAF_RUNTIME_OBJ_WAF_CRON   *gocron.Scheduler        //定时器
)
