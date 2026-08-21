package global

import "sync"

// QpsSample 一次QPS采样点
type QpsSample struct {
	T int64  //采样时刻(unix秒)
	V uint64 //该秒的实时QPS
}

// 采样任务每秒执行一次，保留最近约2分钟
const qpsHistoryCap = 120

var (
	qpsHistoryMu   sync.Mutex
	qpsHistoryBuf  [qpsHistoryCap]QpsSample
	qpsHistoryNext int
	qpsHistoryLen  int
)

// AppendQPSSample 追加一次QPS采样(环形缓冲，写满覆盖最旧)
func AppendQPSSample(ts int64, v uint64) {
	qpsHistoryMu.Lock()
	defer qpsHistoryMu.Unlock()
	qpsHistoryBuf[qpsHistoryNext] = QpsSample{T: ts, V: v}
	qpsHistoryNext = (qpsHistoryNext + 1) % qpsHistoryCap
	if qpsHistoryLen < qpsHistoryCap {
		qpsHistoryLen++
	}
}

// GetQPSHistory 返回最近 limit 个采样点(时间升序)；limit<=0 或超过已有数量时返回全部
func GetQPSHistory(limit int) []QpsSample {
	qpsHistoryMu.Lock()
	defer qpsHistoryMu.Unlock()
	n := qpsHistoryLen
	if limit > 0 && limit < n {
		n = limit
	}
	out := make([]QpsSample, 0, n)
	start := (qpsHistoryNext - n + qpsHistoryCap) % qpsHistoryCap
	for i := 0; i < n; i++ {
		out = append(out, qpsHistoryBuf[(start+i)%qpsHistoryCap])
	}
	return out
}
