package supervisor

// HandoffRestartArg 是 Windows 下拉起"重启助手"用的隐藏命令行参数。
//
// 助手是一个脱离服务的短命进程，唯一职责是等本服务停干净后再把它 start 起来，
// 让 Supervisor 换到新二进制。定义在跨平台文件里，供 cmd/samwaf 的命令分发引用。
const HandoffRestartArg = "handoff-restart"
