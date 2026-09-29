package wafqueue

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"

	"gorm.io/gorm/clause"
)

// PayloadKindEvent 安全事件的报文归属（事件全量留报文）。
// 另外两种 sample（采样负样本）/ watch（观察名单）在 log_tier.go。
const PayloadKindEvent = "event"

// storePayloads 写报文表。单独一条语句，且失败只告警：
// 日志行已经落库，报文丢了详情页显示「未留存报文」，比整批日志一起回滚强。
// 跨批次可能撞上同一个 req_uuid（同一请求分两批入队），主键冲突按「保留先到的」跳过。
func storePayloads(payloads []*model.EventPayload) {
	if len(payloads) == 0 {
		return
	}
	// 不指定冲突列：三个引擎对"无目标的 DO NOTHING"都认（MySQL 走 INSERT IGNORE），
	// 指定了反而要各写各的。这里只有主键一种冲突，无目标正合适。
	err := global.GWAF_LOCAL_LOG_DB.
		Clauses(clause.OnConflict{DoNothing: true}).
		CreateInBatches(payloads, len(payloads)).Error
	if err != nil {
		zlog.Warn("报文落库失败", "条数", len(payloads), "error", err.Error())
	}
}
