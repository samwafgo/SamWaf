package response

// UpgradeNoticeItem 一条升级须知（文案已按请求语言取好）
type UpgradeNoticeItem struct {
	NoticeId     string `json:"notice_id"`
	Version      string `json:"version"`       // 引入版本
	Kind         string `json:"kind"`          // notice / action / check
	Level        string `json:"level"`         // high / normal / low
	Status       string `json:"status"`        // pending / done / ignored
	FreshInstall bool   `json:"fresh_install"` // 是否属于"全新安装建议"

	Title     string `json:"title"`
	Detail    string `json:"detail"`
	EffectOn  string `json:"effect_on"`  // 做了之后有什么变化
	EffectOff string `json:"effect_off"` // 不做会怎样（必须写代价）
	Revert    string `json:"revert"`     // 怎么撤销

	Page      string `json:"page"`       // 「去设置」跳转的站内路径
	Doc       string `json:"doc"`        // 官方文档链接
	ApplyType string `json:"apply_type"` // none / navigate / config_set

	AppliedTime string `json:"applied_time"`
	AppliedUser string `json:"applied_user"`
}

// UpgradeNoticeSummary 顶部提示条与登录弹窗需要的汇总信息
type UpgradeNoticeSummary struct {
	CurrentVersion string `json:"current_version"`
	FromVersion    string `json:"from_version"` // 本次升级的起点，空=无历史记录
	ToVersion      string `json:"to_version"`

	PendingCount     int64 `json:"pending_count"`
	HighPendingCount int64 `json:"high_pending_count"`
	TotalCount       int64 `json:"total_count"`

	// NeedPopup 仅当存在 level=high 且未处理、且从未弹过时为 true。
	// 弹窗一辈子只弹一次，回写靠 /popupshown。
	NeedPopup  bool                `json:"need_popup"`
	PopupItems []UpgradeNoticeItem `json:"popup_items"`

	// Downgrade 旧程序 + 新库（容器重建后回退到镜像自带版本，issue #938）。
	// 过去只打日志、界面完全看不见，这里把它暴露出来。
	Downgrade    bool   `json:"downgrade"`
	DowngradeMsg string `json:"downgrade_msg"`
}
