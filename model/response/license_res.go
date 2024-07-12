package response

import "SamWaf/model"

type LicenseRep struct {
	License   model.RegistrationInfo `json:"license"`    //授权信息
	MachineId string                 `json:"machine_id"` //机器码
	Version   string                 `json:"version"`    //版本
}
