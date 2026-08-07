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
func evtSubscribe(signalEvent windows.Handle, channel, query string) (windows.Handle, error) {
	chPtr, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return 0, err
	}
	var qPtr *uint16
	if query != "" {
		qPtr, err = windows.UTF16PtrFromString(query)
		if err != nil {
			return 0, err
		}
	}

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
		return 0, fmt.Errorf("EvtSubscribe(%s) 失败: %w", channel, e)
	}
	return windows.Handle(r), nil
}

// evtNextXML 等待信号并批量取事件，渲染成 XML 字符串返回。
//
// 返回空切片 + nil 表示"超时且无事件"，这是正常情况——调用方据此回到
// select ctx.Done() 检查是否该退出。超时设成 1 秒，也就决定了 Stop() 的最坏响应时间。
func evtNextXML(sub, signal windows.Handle, timeoutMs uint32) ([]string, error) {
	waitRes, err := windows.WaitForSingleObject(signal, timeoutMs)
	if err != nil {
		return nil, err
	}
	if waitRes == uint32(windows.WAIT_TIMEOUT) {
		return nil, nil
	}
	if err := windows.ResetEvent(signal); err != nil {
		return nil, err
	}

	var out []string
	for {
		handles := make([]windows.Handle, evtNextBatch)
		var returned uint32
		r, _, e := procEvtNext.Call(
			uintptr(sub),
			uintptr(evtNextBatch),
			uintptr(unsafe.Pointer(&handles[0])),
			uintptr(0xFFFFFFFF), // INFINITE：事件已经就绪，不会真的阻塞
			0,
			uintptr(unsafe.Pointer(&returned)),
		)
		if r == 0 {
			// ERROR_NO_MORE_ITEMS 表示这一批取完了，是正常结束
			if errno, ok := e.(syscall.Errno); ok && errno == windows.ERROR_NO_MORE_ITEMS {
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
