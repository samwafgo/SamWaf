package request

type WafGptSendReq struct {
	History [][]string `json:"history"` // 定义结构体
}

// WafGptRuleReq AI 生成自定义规则请求
type WafGptRuleReq struct {
	Intent   string `json:"intent"`    // 用户用自然语言描述的防护需求
	Lang     string `json:"lang"`      // 界面语言 zh_CN / en_US，决定提示词语言
	HostCode string `json:"host_code"` // 可选，所属网站
}

// WafGptConfigSaveReq 保存GPT参数（gpt_url/gpt_model/gpt_token）
// GptToken 为空表示不修改（保留原密钥），非空才覆盖——配合 GET 接口不回传明文，避免密钥泄露
type WafGptConfigSaveReq struct {
	GptUrl   string `json:"gpt_url"`
	GptModel string `json:"gpt_model"`
	GptToken string `json:"gpt_token"`
}
