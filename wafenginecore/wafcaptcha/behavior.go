package wafcaptcha

import (
	"encoding/json"
	"strings"
)

// 传统点选验证码的服务端行为校验。
//
// 挑战页会把本次答题期间的交互信号放在 botCheck 表单字段（JSON）里提交：
// 鼠标/触摸/指针采样、点击次数、看题到交卷的耗时、自动化环境特征数。
// 这些数据来自客户端、天然可伪造——它的定位不是"证明访客是人"，
// 而是把"用无头浏览器打开页面直接点、没有任何人类交互"这类最省事的自动化挡在门外，
// 与交卷接口的按 IP 限频一起抬高批量绕过的成本。
//
// 兼容性：旧版/自定义挑战页不带 v 字段时只做自动化特征判定，
// 避免升级后用户手里未替换的旧页面一夜之间全部无法通过。
const (
	// captchaBehaviorVersion 新挑战页提交的数据格式版本。
	captchaBehaviorVersion = 1
	// captchaBehaviorMinElapsedMs 从题面展示到交卷的人类最短合理耗时（毫秒）。
	captchaBehaviorMinElapsedMs = 500
)

type captchaBehaviorPoint struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
	T float64 `json:"t"`
}

// captchaBehavior 与挑战页 behavior.snapshot() 的字段一一对应。
type captchaBehavior struct {
	V             int                    `json:"v"`             // 数据格式版本，新页面固定为 1
	MousePoints   int                    `json:"mousePoints"`   // 鼠标移动采样点数
	TouchPoints   int                    `json:"touchPoints"`   // 触摸事件数
	PointerPoints int                    `json:"pointerPoints"` // 指针事件数（覆盖触控笔等设备）
	Clicks        int                    `json:"clicks"`        // 点击次数
	MouseTrack    []captchaBehaviorPoint `json:"mouseTrack"`    // 鼠标轨迹（最多 100 个采样点）
	ElapsedMs     int64                  `json:"elapsedMs"`     // 从题面展示到交卷的耗时
	Auto          int                    `json:"auto"`          // 客户端命中的自动化环境特征数
}

// checkCaptchaBehavior 校验行为数据，返回 (是否通过, 未通过原因)。
func checkCaptchaBehavior(raw string) (bool, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		// 没有行为数据不拒绝：旧版/自定义挑战页可能不带 botCheck 字段，
		// 误伤真人的代价（验证永远过不去）远高于放过这一层信号。
		return true, ""
	}

	var b captchaBehavior
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		return false, "行为数据格式错误"
	}
	if b.Auto > 0 {
		return false, "检测到自动化环境特征"
	}
	if b.V < captchaBehaviorVersion {
		// 旧版数据没有采集耗时与轨迹，无法做进一步判断。
		return true, ""
	}
	if b.ElapsedMs <= 0 {
		return false, "缺少答题耗时"
	}
	if b.ElapsedMs < captchaBehaviorMinElapsedMs {
		return false, "答题耗时异常"
	}
	if b.MousePoints == 0 && b.TouchPoints == 0 && b.PointerPoints == 0 {
		// 勾选多个位置必然产生移动：没有任何鼠标/触摸/指针交互的"连点"是脚本特征。
		return false, "缺少人机交互轨迹"
	}
	if b.Clicks < 2 {
		// 点选至少两个目标字符，点击次数不可能低于 2。
		return false, "点击次数异常"
	}
	for i := 1; i < len(b.MouseTrack); i++ {
		if b.MouseTrack[i].T < b.MouseTrack[i-1].T {
			// 采样时间戳必须单调不减，倒序说明轨迹是拼出来的。
			return false, "交互轨迹时间戳异常"
		}
	}
	return true, ""
}
