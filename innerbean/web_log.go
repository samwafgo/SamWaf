package innerbean

import "strings"

type WebLog struct {
	WafInnerDFlag        string `json:"waf_inner_dflag"` //日志队列处理方式
	HOST                 string `json:"host"`
	URL                  string `json:"url"`
	RawQuery             string `json:"raw_query"` //原始URL查询
	REFERER              string `json:"referer"`
	USER_AGENT           string `json:"user_agent"`
	METHOD               string `json:"method"`
	HEADER               string `json:"header"`
	SRC_IP               string `json:"src_ip"`
	SRC_PORT             string `json:"src_port"`
	COUNTRY              string `json:"country"`
	PROVINCE             string `json:"province"`
	CITY                 string `json:"city"`
	CREATE_TIME          string `gorm:"index:idx_weblog_time" json:"create_time"`
	CONTENT_LENGTH       int64  `json:"content_length"`
	COOKIES              string `json:"cookies"`
	BODY                 string `json:"body"`
	REQ_UUID             string `json:"req_uuid"`
	USER_CODE            string `json:"user_code" gorm:"index"`
	TenantId             string `json:"tenant_id" gorm:"index"` //租户ID（主要键）
	HOST_CODE            string `json:"host_code" `             //主机ID （主要键）
	Day                  int    `json:"day"`                    //日 （主要键）
	ACTION               string `json:"action"`
	RULE                 string `json:"rule"`
	STATUS               string `json:"status"`                            //状态
	STATUS_CODE          int    `json:"status_code"`                       //状态编码
	RES_BODY             string `json:"res_body"`                          //返回信息
	POST_FORM            string `json:"post_form"`                         //提交的表单数据
	TASK_FLAG            int    `json:"task_flag" gorm:"default:-1;index"` //任务处理标记 -1 等待处理；1 可以进行处理；2 处理完毕
	UNIX_ADD_TIME        int64  `json:"unix_add_time" gorm:"index"`        //添加日期unix
	RISK_LEVEL           int    `json:"risk_level"`                        //危险等级 0:正常 1:轻微 2:有害 3:严重 4:特别严重
	GUEST_IDENTIFICATION string `json:"guest_identification"`              //访客身份识别
	IsBot                int    `json:"is_bot"`                            //是否是机器人  0 不是机器人 1 机器人
	TimeSpent            int64  `json:"time_spent"`                        //用时
	NetSrcIp             string `json:"net_src_ip"`                        //获取的原始IP
	SrcByteBody          []byte `json:"src_byte_body"`                     //原始body信息
	SrcByteResBody       []byte `json:"src_byte_res_body"`                 //返回body bytes信息
	WebLogVersion        int    `json:"web_log_version"`                   //日志版本信息早期的是空和0，后期实时增加
	Scheme               string `json:"scheme"`                            //HTTP 协议
	SrcURL               []byte `json:"src_url"`                           //原始url信息
	PreCheckCost         int64  `json:"pre_check_cost"`                    // 前置检查耗时(ms)
	ForwardCost          int64  `json:"forward_cost"`                      // 转发耗时(ms)
	BackendCheckCost     int64  `json:"backend_check_cost"`                // 后端处理耗时(ms)
	ResHeader            string `json:"res_header"`                        // 返回header情况
	BodyHash             string `json:"body_hash"`                         // body hash值
	LogOnlyMode          int    `json:"log_only_mode"`                     //是否只记录日志 1 是 0 不是
	IsBalance            int    `json:"is_balance"`                        //是否是负载均衡 1 是 0 不是
	BalanceInfo          string `json:"balance_info"`                      //负载均衡IP端口信息
}

// GetHeaderValue 从HEADER字段中提取指定header的值
// headerName: 要查找的header名称（不区分大小写）
// 返回: header的值，如果不存在则返回空字符串
func (w *WebLog) GetHeaderValue(headerName string) string {
	if w.HEADER == "" || headerName == "" {
		return ""
	}

	// 将header名称转换为小写进行比较
	headerName = strings.ToLower(headerName)

	// 按行分割header字符串
	lines := strings.Split(w.HEADER, "\r\n")

	for _, line := range lines {
		// 跳过空行
		if strings.TrimSpace(line) == "" {
			continue
		}

		// 查找冒号分隔符
		colonIndex := strings.Index(line, ":")
		if colonIndex == -1 {
			continue
		}

		// 提取header名称和值
		key := strings.ToLower(strings.TrimSpace(line[:colonIndex]))
		value := strings.TrimSpace(line[colonIndex+1:])

		// 如果找到匹配的header，返回其值
		if key == headerName {
			return value
		}
	}

	// 未找到指定的header，返回空字符串
	return ""
}

// 在 GORM 的 Model 方法中定义复合索引
func (WebLog) TableName() string {
	return "web_logs"
}

// GetIPFailureCount 获取IP在指定时间窗口内的失败次数（用于规则引擎）
// minutes: 时间窗口（分钟）
// 返回: 失败次数
func (w *WebLog) GetIPFailureCount(minutes int64) int64 {
	if w.SRC_IP == "" {
		return 0
	}
	// 直接调用IP失败管理器（延迟导入避免编译时循环依赖）
	return getIPFailureCount(w.SRC_IP, minutes)
}

// getIPFailureCount 获取IP失败次数（通过函数变量实现延迟导入）
var getIPFailureCount func(string, int64) int64

// SetIPFailureCountGetter 设置IP失败次数获取函数
func SetIPFailureCountGetter(fn func(string, int64) int64) {
	getIPFailureCount = fn
}

type WAFLog struct {
	REQ_UUID    string `json:"req_uuid"`
	ACTION      string `json:"action"`
	RULE        string `json:"rule"`
	CREATE_TIME string `json:"create_time"`
	USER_CODE   string `json:"user_code"`
}
