package request

type WafLoginOutReq struct {
	AccountToken string `json:"account_token" form:"account_token"`
}
