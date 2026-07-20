//go:build crossdb

// core 库 CRUD 三库回归 —— 批 B：签名/流程较特殊的 service
// （PrivateInfo 按 key 改、Rule 多裸参+软删、SslConfig 需 PEM、OPlatformKey 返回密钥、
//
//	Center 无删、以及 #885 CreateInner 三库回归守卫）。
package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/model"
	"SamWaf/model/request"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"gorm.io/gorm"
)

// genSelfSignedCert 现生成一张自签 ECDSA 证书（免联网），供 SslConfig 用例。
func genSelfSignedCert(t *testing.T, cn string) (certPEM, keyPEM string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	serial, err := crand.Int(crand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("生成序列号失败: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(crand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("生成证书失败: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDer, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("序列化密钥失败: %v", err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer}))
	return
}

func runCoreCRUDCasesB(t *testing.T, db *gorm.DB) {
	t.Run("PrivateInfo", func(t *testing.T) {
		key := "pk_" + sfx()
		grp := "g_" + sfx()
		fatalIf(t, WafPrivateInfoServiceApp.AddApi(request.WafPrivateInfoAddReq{
			PrivateKey: key, PrivateValue: "v1", PrivateGroupName: grp, PrivateGroupBelongCloud: "tencent", Remarks: "r",
		}))
		var bean model.PrivateInfo
		firstBy(t, db, &bean, "private_key = ?", key)
		fatalIf(t, WafPrivateInfoServiceApp.ModifyApi(request.WafPrivateInfoEditReq{
			PrivateKey: key, PrivateValue: "v2", PrivateGroupName: grp, PrivateGroupBelongCloud: "tencent",
		}))
		got := WafPrivateInfoServiceApp.GetDetailByIdApi(bean.Id)
		if got.PrivateValue != "v2" {
			t.Fatalf("PrivateInfo 更新未落库: %+v", got)
		}
		fatalIf(t, WafPrivateInfoServiceApp.DelApi(request.WafPrivateInfoDelReq{Id: bean.Id}))
		assertGone(t, db, &model.PrivateInfo{}, bean.Id)
	})

	t.Run("HostPathRule", func(t *testing.T) {
		name := "hpr_" + sfx()
		fatalIf(t, WafHostPathRuleServiceApp.AddApi(request.WafHostPathRuleAddReq{
			HostCode: "h1", RuleName: name, Path: "/api/", MatchType: 1, Priority: 100, TargetType: 1, RemoteHost: "backend", RemotePort: 8080,
		}))
		var bean model.HostPathRule
		firstBy(t, db, &bean, "rule_name = ?", name)
		fatalIf(t, WafHostPathRuleServiceApp.ModifyApi(request.WafHostPathRuleEditReq{
			Id: bean.Id, HostCode: "h2", RuleName: name, Path: "/v2/", MatchType: 2, Priority: 50, TargetType: 1, RemoteHost: "backend2", RemotePort: 9090,
		}))
		var got model.HostPathRule
		firstBy(t, db, &got, "id = ?", bean.Id)
		if got.HostCode != "h2" || got.Path != "/v2/" || got.RemotePort != 9090 {
			t.Fatalf("HostPathRule 更新未落库: %+v", got)
		}
		fatalIf(t, WafHostPathRuleServiceApp.DelApi(request.WafHostPathRuleDelReq{Id: bean.Id}))
		assertGone(t, db, &model.HostPathRule{}, bean.Id)
	})

	t.Run("Center", func(t *testing.T) {
		tid := "ct_" + sfx()
		uc := "uc_" + sfx()
		fatalIf(t, CenterServiceApp.AddApi(request.CenterClientUpdateReq{
			ClientServerName: "s1", ClientUserCode: uc, ClientTenantId: tid, ClientIP: "1.2.3.4", ClientPort: "80",
		}))
		bean := CenterServiceApp.GetDetailByTencentUserCode(tid, uc)
		if bean.Id == "" {
			t.Fatalf("Center 新增后未定位到记录")
		}
		fatalIf(t, CenterServiceApp.ModifyApi(request.CenterClientUpdateReq{
			ClientServerName: "s2", ClientUserCode: uc, ClientTenantId: tid, ClientIP: "5.6.7.8", ClientPort: "443",
		}))
		got := CenterServiceApp.GetDetailByTencentUserCode(tid, uc)
		if got.ClientServerName != "s2" || got.ClientIP != "5.6.7.8" {
			t.Fatalf("Center 更新未落库: %+v", got)
		}
	})

	t.Run("OPlatformKey", func(t *testing.T) {
		name := "ak_" + sfx()
		id, apiKey, err := WafOPlatformKeyServiceApp.AddApi(request.WafOPlatformKeyAddReq{KeyName: name, Remark: "r", RateLimit: 60})
		fatalIf(t, err)
		if id == "" || apiKey == "" {
			t.Fatalf("OPlatformKey AddApi 返回空: id=%q apiKey=%q", id, apiKey)
		}
		fatalIf(t, WafOPlatformKeyServiceApp.ModifyApi(request.WafOPlatformKeyEditReq{Id: id, KeyName: name + "_x", Status: 0, Remark: "r2", RateLimit: 120}))
		got := WafOPlatformKeyServiceApp.GetDetailApi(request.WafOPlatformKeyDetailReq{Id: id})
		if got.KeyName != name+"_x" || got.Status != 0 {
			t.Fatalf("OPlatformKey 更新未落库: %+v", got)
		}
		fatalIf(t, WafOPlatformKeyServiceApp.DelApi(request.WafOPlatformKeyDelReq{Id: id}))
		assertGone(t, db, &model.OPlatformKey{}, id)
	})

	t.Run("SslExpire", func(t *testing.T) {
		domain := "d_" + sfx() + ".com"
		fatalIf(t, WafSslExpireServiceApp.AddApi(request.WafSslExpireAddReq{Domain: domain, Port: 443, VisitLog: "v", Status: "unknown"}))
		var bean model.SslExpire
		firstBy(t, db, &bean, "domain = ?", domain)
		fatalIf(t, WafSslExpireServiceApp.ModifyApi(request.WafSslExpireEditReq{Id: bean.Id, Domain: domain, Port: 8443, VisitLog: "v2", Status: "valid"}))
		got := WafSslExpireServiceApp.GetDetailByIdApi(bean.Id)
		if got.Port != 8443 || got.Status != "valid" {
			t.Fatalf("SslExpire 更新未落库: %+v", got)
		}
		fatalIf(t, WafSslExpireServiceApp.DelApi(request.WafSslExpireDelReq{Id: bean.Id}))
		assertGone(t, db, &model.SslExpire{}, bean.Id)
	})

	t.Run("Rule_FullCRUD", func(t *testing.T) {
		code := uuid.GenUUID()
		name := "rule_" + sfx()
		fatalIf(t, WafRuleServiceApp.AddApi(request.WafRuleAddReq{RuleCode: code, IsManualRule: 1, RuleStatus: 1}, code, name, "h1", "content-v1"))
		if got := WafRuleServiceApp.GetDetailByCodeApi(code); got.RuleContent != "content-v1" || got.RuleName != name {
			t.Fatalf("Rule 新增未落库: %+v", got)
		}
		fatalIf(t, WafRuleServiceApp.ModifyApi(request.WafRuleEditReq{CODE: code, IsManualRule: 1, RuleStatus: 1}, name, "h1", "content-v2"))
		if got := WafRuleServiceApp.GetDetailByCodeApi(code); got.RuleContent != "content-v2" {
			t.Fatalf("Rule 更新未落库: %+v", got)
		}
		// DelRuleApi 是软删（RuleStatus=999）：GetDetailByCodeApi 会隐藏 999 行，
		// 故直接读库断言状态位（bypass 服务层的 <>999 过滤）。
		fatalIf(t, WafRuleServiceApp.DelRuleApi(request.WafRuleDelReq{CODE: code}))
		var deleted model.Rules
		firstBy(t, db, &deleted, "rule_code = ?", code)
		if deleted.RuleStatus != 999 {
			t.Fatalf("Rule 软删后 rule_status 应为 999，实际 %d", deleted.RuleStatus)
		}
		// 且服务层的 GetDetailByCodeApi 应查不到（被 999 过滤隐藏）
		if got := WafRuleServiceApp.GetDetailByCodeApi(code); got.Id != "" {
			t.Fatalf("软删后 GetDetailByCodeApi 仍返回记录: %+v", got)
		}
	})

	t.Run("SslConfig", func(t *testing.T) {
		cn := "t" + sfx() + ".example.com"
		cert1, key1 := genSelfSignedCert(t, cn)
		fatalIf(t, WafSslConfigServiceApp.AddApi(request.SslConfigAddReq{CertContent: cert1, KeyContent: key1}))
		var bean model.SslConfig
		firstBy(t, db, &bean, "domains = ?", cn)
		if bean.SerialNo == "" {
			t.Fatalf("SslConfig 新增后序列号为空: %+v", bean)
		}
		cn2 := "u" + sfx() + ".example.com"
		cert2, key2 := genSelfSignedCert(t, cn2)
		fatalIf(t, WafSslConfigServiceApp.ModifyApi(request.SslConfigEditReq{Id: bean.Id, CertContent: cert2, KeyContent: key2}))
		got := WafSslConfigServiceApp.GetDetailInner(bean.Id)
		if got.Domains != cn2 {
			t.Fatalf("SslConfig 更新未落库: domains=%q 期望 %q", got.Domains, cn2)
		}
		fatalIf(t, WafSslConfigServiceApp.DelApi(request.SslConfigDeleteReq{Id: bean.Id}))
		assertGone(t, db, &model.SslConfig{}, bean.Id)
	})

	// #885 三库回归守卫：CreateInner（按值 model + AutoLoadPath=0）不崩且正确落 0
	t.Run("SslConfig_CreateInner_885", func(t *testing.T) {
		s, err := crand.Int(crand.Reader, new(big.Int).Lsh(big.NewInt(1), 140))
		fatalIf(t, err)
		serial := s.String() // 超长十进制序列号，还原 #885 现场
		cfg := model.SslConfig{
			BaseOrm:      newBase(uuid.GenUUID()),
			SerialNo:     serial,
			Domains:      "inner_" + sfx() + ".example.com",
			AutoLoadPath: 0, // 自动管理证书：关闭路径自动加载
		}
		// 修复前：按值 Create + 零值默认列在此 panic（reflect.Value.SetInt unaddressable）
		WafSslConfigServiceApp.CreateInner(cfg)
		var got model.SslConfig
		firstBy(t, db, &got, "serial_no = ?", serial)
		if got.AutoLoadPath != 0 {
			t.Fatalf("CreateInner 后 auto_load_path 应为 0，实际 %d", got.AutoLoadPath)
		}
	})
}
