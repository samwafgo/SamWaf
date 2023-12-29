package request

type WafAttackLogDetailReq struct {
	CurrrentDbName string `json:"current_db_name"`
	REQ_UUID       string `json:"req_uuid"`
}
