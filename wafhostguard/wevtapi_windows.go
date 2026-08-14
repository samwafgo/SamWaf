//go:build windows

package wafhostguard

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// wevtapi.dll 的最小绑定，只覆盖"订阅未来事件并渲染成 XML"这一条路径。
//
// **用拉模式(SignalEvent)而不是回调模式**：回调由非 Go 线程发起，
// syscall.NewCallback 创建的回调有数量上限、且在高频事件下涉及跨线程栈切换，
// 出问题很难排查。拉模式就是普通的"等信号 -> 取一批 -> 处理"，没有这些风险。
//
// 全部原语(CreateEvent / WaitForSingleObject / ResetEvent)golang.org/x/sys/windows
// 都已提供，不需要引入任何第三方依赖，也不需要 CGO。

var (
	modWevtapi       = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtSubscribe = modWevtapi.NewProc("EvtSubscribe")
	procEvtNext      = modWevtapi.NewProc("EvtNext")
	procEvtRender    = modWevtapi.NewProc("EvtRender")
	procEvtClose     = modWevtapi.NewProc("EvtClose")
)

const (
	// EvtSubscribeToFutureEvents：只要订阅之后新产生的事件。
	// 和 tail 从文件末尾开始是同一个道理——回放历史会把陈年旧事当成正在发生的攻击。
	evtSubscribeToFutureEvents = 1
	// EvtRenderEventXml：把事件渲染成 XML 文本
	evtRenderEventXml = 1
	// 单次最多取多少条事件
	evtNextBatch = 16
	// evtNextTimeoutMs EvtNext 自身的等待上限。取得短一点即可：
	// 外层已经在按节奏轮询，这里没必要再等。
	evtNextTimeoutMs = 100
)

// EvtNext 在"当前没有可取事件"时会返回的几个错误码。
// windows 包里没有现成常量，直接按 winerror.h 的值定义。
const (
	errInvalidOperation syscall.Errno = 4317 // ERROR_INVALID_OPERATION
	errWaitTimeout      syscall.Errno = 1460 // ERROR_TIMEOUT
)

// wevtAvailable 报告 wevtapi.dll 是否可加载。加载不了就走 wevtutil 降级通道。
func wevtAvailable() error {
	if err := modWevtapi.Load(); err != nil {
		return fmt.Errorf("加载 wevtapi.dll 失败: %w", err)
	}
	for _, p := range []*windows.LazyProc{procEvtSubscribe, procEvtNext, procEvtRender, procEvtClose} {
		if err := p.Find(); err != nil {
			return fmt.Errorf("wevtapi.dll 缺少所需函数: %w", err)
		}
	}
	return nil
}

// evtSubscribe 订阅指定频道的未来事件。
// signalEvent 由 windows.CreateEvent 创建(手动重置)，有新事件时被置位。
//
// **chPtr / qPtr 必须由调用方持有到退订为止。** 订阅是长期存活的对象，
// 而这两块内存是 Go 分配的；调用返回后若没人引用，GC 随时可以回收它们。
// wevtapi 是否在内部拷贝了字符串并无文档保证，按 unsafe.Pointer 的使用规则，
// 传给系统调用且可能被对方留存的指针必须显式保活——否则就是未定义行为，
// 而这类问题的典型表现恰恰是"订阅建得起来、却一条事件都不投递"。
func evtSubscribe(signalEvent windows.Handle, chPtr, qPtr *uint16) (windows.Handle, error) {
	r, _, e := procEvtSubscribe.Call(
		0,                              // Session：本机
		uintptr(signalEvent),           // SignalEvent
		uintptr(unsafe.Pointer(chPtr)), // ChannelPath
		uintptr(unsafe.Pointer(qPtr)),  // Query
		0,                              // Bookmark
		0,                              // Context
		0,                              // Callback（拉模式不用）
		uintptr(evtSubscribeToFutureEvents),
	)
	if r == 0 {
		return 0, fmt.Errorf("EvtSubscribe 失败: %w", e)
	}
	return windows.Handle(r), nil
}

// evtNextXML 取一批事件，渲染成 XML 字符串返回。
//
// **不能只在信号量置位后才去取。** 实测 Windows Server 2022 上 EvtSubscribe
// 从不置位 SignalEvent(诊断工具测得置位 0 次)，但订阅本身一直在正常收集事件——
// 直接轮询 EvtNext 就能把事件取出来。只等信号量的写法会导致"订阅建得起来、
// 一条事件都收不到、还不报任何错"，是最难排查的一种失效。
//
// 所以这里改成：等信号量最多 timeoutMs，**无论是否等到都去取一次**。
// 信号量正常的机器仍然是事件一来就响应，不正常的机器最多延迟 timeoutMs。
//
// 返回空切片 + nil 表示"这一轮没有新事件"，是正常情况。
func evtNextXML(sub, signal windows.Handle, timeoutMs uint32) ([]string, error) {
	waitRes, err := windows.WaitForSingleObject(signal, timeoutMs)
	if err != nil {
		return nil, err
	}
	if waitRes == uint32(windows.WAIT_OBJECT_0) {
		if err := windows.ResetEvent(signal); err != nil {
			return nil, err
		}
	}

	var out []string
	for {
		handles := make([]windows.Handle, evtNextBatch)
		var returned uint32
		r, _, e := procEvtNext.Call(
			uintptr(sub),
			uintptr(evtNextBatch),
			uintptr(unsafe.Pointer(&handles[0])),
			// **不能用 INFINITE**：轮询模式下多数轮次本就没有新事件，
			// 用 INFINITE 会把整个采集循环永久阻塞在这里。
			uintptr(evtNextTimeoutMs),
			0,
			uintptr(unsafe.Pointer(&returned)),
		)
		if r == 0 {
			// 这三个错误码都表示"这一批取完了"，不是故障：
			//   ERROR_NO_MORE_ITEMS    没有更多事件
			//   ERROR_INVALID_OPERATION 订阅句柄上无事件可取时的另一种返回(实测 Server 2022)
			//   ERROR_TIMEOUT          等待新事件超时
			// 尤其是 ERROR_INVALID_OPERATION，不认它就会被当成真故障反复报警。
			if errno, ok := e.(syscall.Errno); ok &&
				(errno == windows.ERROR_NO_MORE_ITEMS ||
					errno == errInvalidOperation ||
					errno == errWaitTimeout) {
				return out, nil
			}
			if len(out) > 0 {
				return out, nil
			}
			return nil, fmt.Errorf("EvtNext 失败: %w", e)
		}

		for i := uint32(0); i < returned; i++ {
			h := handles[i]
			if xmlStr, err := evtRenderXML(h); err == nil {
				out = append(out, xmlStr)
			}
			procEvtClose.Call(uintptr(h))
		}
		if returned < evtNextBatch {
			return out, nil
		}
	}
}

// evtRenderXML 把单个事件句柄渲染成 XML。
// 先用小缓冲试，不够再按系统告知的大小重来一次——事件大小差异很大，
// 一上来就分配大缓冲在高频场景下太浪费。
func evtRenderXML(h windows.Handle) (string, error) {
	buf := make([]uint16, 4096)
	var used, propCount uint32

	render := func(b []uint16) (uintptr, error) {
		r, _, e := procEvtRender.Call(
			0, // Context
			uintptr(h),
			uintptr(evtRenderEventXml),
			uintptr(len(b)*2), // BufferSize，字节数
			uintptr(unsafe.Pointer(&b[0])),
			uintptr(unsafe.Pointer(&used)),
			uintptr(unsafe.Pointer(&propCount)),
		)
		return r, e
	}

	r, e := render(buf)
	if r == 0 {
		if errno, ok := e.(syscall.Errno); ok && errno == windows.ERROR_INSUFFICIENT_BUFFER {
			buf = make([]uint16, used/2+1)
			if r, e = render(buf); r == 0 {
				return "", fmt.Errorf("EvtRender 失败: %w", e)
			}
		} else {
			return "", fmt.Errorf("EvtRender 失败: %w", e)
		}
	}
	return windows.UTF16ToString(buf), nil
}

// evtClose 释放订阅句柄
func evtClose(h windows.Handle) {
	if h != 0 {
		procEvtClose.Call(uintptr(h))
	}
}
