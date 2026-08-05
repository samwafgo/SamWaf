package enums

const (
	BATCHTASK_IPALLOW = "ipallow"
	BATCHTASK_IPDENY  = "ipdeny"
	// BATCHTASK_IPGROUP 导入到 IP 组。IP 组是租户级资源、不带 host_code，
	// 目标组由 batch_extra_config 里的 group_code 指定，与 batch_host_code 无关。
	BATCHTASK_IPGROUP                = "ipgroup"
	BATCHTASK_SENSITIVE              = "sensitive"
	BATCHTASK_EXECUTEMETHODAPPEND    = "append"
	BATCHTASK_EXECUTEMETHODOVERWRITE = "overwrite"
)
