package wafhostguard

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/utils"
	"SamWaf/wafipban"
	"fmt"
	"time"
)

// 判定引擎：一条归一化事件进来，决定它要不要计数、要不要触发封禁。
//
// 闸门顺序是有讲究的，越"便宜"、越"确定不该封"的判断放在越前面：
// 硬开关 → 软失败过滤 → 白名单 → 计数 → 阈值。
// 白名单排在计数之前，是为了让自己人的失败连计数都不产生——
// 否则管理员敲错几次密码，虽然不会被封，但会在攻击者档案里留下莫名其妙的记录。

// eventSink 事件落库回调。由 engine 注入，避免 wafhostguard 直接依赖 service 层
// 造成 service -> wafhostguard -> service 的循环引用。
type eventSink func(model.HostLoginEvent)

var recordEvent eventSink

// SetEventSink 注入事件落库实现
func SetEventSink(fn eventSink) { recordEvent = fn }

// Decide 处理一条登录失败事件，返回处置结果(供调用方统计)
func Decide(ev LoginFailEvent) BanResult {
	res := BanResult{TargetIP: ev.IP}
	now := ev.At
	if now.IsZero() {
		now = time.Now()
	}

	action := model.HostEventActionCounted

	// 1. 硬开关：连事件都不记，彻底安静
	if global.GCONFIG_HOST_GUARD_FORCE_DISABLE {
		res.Skipped = "已被配置文件强制关闭"
		return res
	}

	// 2. 软失败过滤。preauth 断连/用户名枚举/PAM 行默认不计数，
	//    原因见 FailKind.IsHard 的注释——它们要么是扫描噪声，要么会与密码失败行重复。
	countable := ev.Kind.IsHard() || global.GCONFIG_HOST_GUARD_COUNT_SOFT_FAIL == 1

	// 3. 白名单
	white, whiteReason := IsWhitelisted(ev.IP)
	if white {
		countable = false
		action = model.HostEventActionSkipped
		zlog.Debug("[主机登录防护] 白名单豁免", "ip", ev.IP, "原因", whiteReason)
	}

	var hitCount int64
	if countable {
		mgr := wafipban.GetHostLoginFailureManager()
		if mgr != nil {
			window := global.GCONFIG_HOST_GUARD_FIND_TIME
			if window <= 0 {
				window = 10
			}
			// 事件保留窗口取统计窗口的 3 倍，让页面上还能看到"刚过窗口"的历史，
			// 同时不至于无限增长
			hitCount = mgr.Record(ev.Source, ev.IP, window, window*3)
		}
	} else if !white {
		action = model.HostEventActionSkipped
	}

	// 4. 阈值判定
	maxRetry := global.GCONFIG_HOST_GUARD_MAX_RETRY
	if maxRetry <= 0 {
		maxRetry = 8
	}
	if countable && hitCount >= maxRetry {
		res = ApplyBan(BanRequest{
			IP:        ev.IP,
			Source:    ev.Source,
			HitCount:  hitCount,
			FailKinds: describeEvent(ev),
		}, now)

		switch {
		case res.Banned:
			action = model.HostEventActionBanned
			// 封禁下发后清空计数：否则解封瞬间那些旧事件还在保留窗口里，
			// 下一条失败就会立刻把它顶回阈值，用户看到的是"封了 5 分钟，
			// 解封后 1 秒又被封"，阶梯也会被无意义地快速推高。
			if mgr := wafipban.GetHostLoginFailureManager(); mgr != nil {
				mgr.Clear(ev.Source, ev.IP)
			}
		case res.Observed:
			action = model.HostEventActionObserve
		default:
			action = model.HostEventActionSkipped
		}
	}

	// 5. 落库(异步批量，见 service 层)
	if recordEvent != nil {
		recordEvent(model.HostLoginEvent{
			Source:    ev.Source,
			IP:        ev.IP,
			Port:      ev.Port,
			UserName:  ev.User,
			FailKind:  string(ev.Kind),
			LogonType: ev.LogonType,
			Location:  utils.FormatIPLocation(ev.IP),
			Action:    action,
			HitCount:  hitCount,
			RawLine:   ev.Raw,
			EventTime: now.Unix(),
		})
	}

	return res
}

// describeEvent 生成一句失败摘要，写进封禁原因里让用户看得懂是怎么被封的
func describeEvent(ev LoginFailEvent) string {
	kindName := FailKindName(ev.Kind)
	if ev.User == "" {
		return kindName
	}
	return fmt.Sprintf("%s，最近尝试账号 %s", kindName, ev.User)
}

// FailKindName 失败类型的中文名，前端与通知文案共用
func FailKindName(k FailKind) string {
	switch k {
	case FailPassword:
		return "密码错误"
	case FailPublicKey:
		return "公钥认证失败"
	case FailInvalidUser:
		return "用户名不存在"
	case FailMaxAuthTries:
		return "单连接内尝试次数超限"
	case FailNotAllowed:
		return "账号不在允许列表"
	case FailPamAuth:
		return "PAM认证失败"
	case FailPreauthClose:
		return "认证前断开连接"
	case FailRdpLogon:
		return "远程桌面登录失败"
	default:
		return string(k)
	}
}
