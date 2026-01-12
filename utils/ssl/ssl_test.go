package ssl

import (
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"testing"
)

func TestRegistrationSSL(t *testing.T) {
	order := model.SslOrder{
		BaseOrm:                 baseorm.BaseOrm{},
		ApplyPlatform:           "letsencrypt",
		ApplyMethod:             "http",
		ApplyDns:                "",
		ApplyEmail:              "samwafgo@gmail.com",
		ApplyDomain:             "ssl.samwaf.com",
		ApplyStatus:             "",
		ResultDomain:            "",
		ResultCertURL:           "",
		ResultCertStableURL:     "",
		ResultPrivateKey:        nil,
		ResultCertificate:       nil,
		ResultIssuerCertificate: nil,
		ResultCSR:               nil,
		Remarks:                 "",
	}
	RegistrationSSL(order, "C:\\huawei\\goproject\\SamWaf\\data\\vhost\\ssl#samwaf#com", "https://acme-v02.api.letsencrypt.org/directory", "letsencrypt", "", "")
}
