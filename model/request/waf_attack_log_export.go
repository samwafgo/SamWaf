package request

type WafAttackLogDoExport struct {
	CurrrentDbName string `json:"current_db_name"`
	HostCode       string `json:"host_code" form:"host_code"` //主机码
}
