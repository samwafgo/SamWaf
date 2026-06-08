package wafappmodel

import (
	"os/exec"
	"sync"
	"time"
)

// 保留 time 供 StartTime 字段使用

const (
	AppStatusStopped = 0
	AppStatusRunning = 1
	AppStatusCrashed = 2
)

type AppRuntime struct {
	Code         string
	Pid          int
	Status       int
	StartTime    time.Time
	RestartCount int
	LogLines     []string
	LogMu        sync.Mutex
	Cmd          *exec.Cmd
	StopChan     chan struct{} // 关闭后阻止 monitorApp 自动重启
	Done         chan struct{} // monitorApp 退出时关闭，供 StopApp 等待
}

type BackupInfo struct {
	Filename  string `json:"filename"`
	Size      int64  `json:"size"`
	CreatedAt string `json:"created_at"`
}

type PortInfo struct {
	Protocol  string `json:"protocol"`
	LocalAddr string `json:"local_addr"`
	Port      int    `json:"port"`
	State     string `json:"state"`
	Pid       int    `json:"pid"`
}

type ConnInfo struct {
	Protocol   string `json:"protocol"`
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
	RemoteIP   string `json:"remote_ip"`
	State      string `json:"state"`
	Pid        int    `json:"pid"`
}

type NetStatsResult struct {
	Ports       []PortInfo `json:"ports"`
	Connections []ConnInfo `json:"connections"`
	CachedAt    string     `json:"cached_at"`
	Pid         int        `json:"pid"`
	Pids        []int      `json:"pids"`
}
