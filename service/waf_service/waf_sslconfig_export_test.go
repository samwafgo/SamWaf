package waf_service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"

	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 证书导出（issue #929）service 层用例。
// 关注点：默认关闭、导出成功、各种坏输入下"只失败不影响主流程"、以及不覆盖别人的文件。

// setupSslExportTestDB 建一个临时 sqlite 库，接管全局 DB 并在用例结束后还原。
func setupSslExportTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(
		sqlite.Open(filepath.Join(t.TempDir(), "sslexport_test.db")),
		&gorm.Config{Logger: logger.Default.LogMode(logger.Silent)},
	)
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	if err := db.AutoMigrate(&model.SslConfig{}, &model.Hosts{}); err != nil {
		t.Fatalf("AutoMigrate 失败: %v", err)
	}
	oldDB, oldTenant, oldUser := global.GWAF_LOCAL_DB, global.GWAF_TENANT_ID, global.GWAF_USER_CODE
	global.GWAF_LOCAL_DB = db
	global.GWAF_TENANT_ID, global.GWAF_USER_CODE = "SamWafCom", "user-uuid-sslexport"
	t.Cleanup(func() {
		global.GWAF_LOCAL_DB = oldDB
		global.GWAF_TENANT_ID, global.GWAF_USER_CODE = oldTenant, oldUser
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

// genExportTestCert 现生成一张自签证书（免联网），供导出用例使用。
func genExportTestCert(t *testing.T, cn string) (certPEM, keyPEM string) {
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

// addSslConfigForExport 走真实的 AddApi 建一条证书夹，返回ID和证书内容。
func addSslConfigForExport(t *testing.T, cn, exportCert, exportKey string) (string, string, string) {
	t.Helper()
	certPEM, keyPEM := genExportTestCert(t, cn)
	id, err := WafSslConfigServiceApp.AddApi(request.SslConfigAddReq{
		CertContent:    certPEM,
		KeyContent:     keyPEM,
		ExportCertPath: exportCert,
		ExportKeyPath:  exportKey,
	})
	if err != nil {
		t.Fatalf("新增证书夹失败: %v", err)
	}
	return id, certPEM, keyPEM
}

func TestExport_未配置导出路径时静默跳过(t *testing.T) {
	setupSslExportTestDB(t)

	id, _, _ := addSslConfigForExport(t, "noexport.example.com", "", "")
	msg, err := WafSslConfigServiceApp.ExportById(id)
	if err != nil {
		t.Fatalf("未配置导出不应报错: %v", err)
	}
	if msg != "" {
		t.Fatalf("未配置导出不应返回提示: %q", msg)
	}
	// 不该在库里留下任何导出状态，否则前端会显示一条莫名其妙的记录
	if got := WafSslConfigServiceApp.GetDetailInner(id); got.ExportStatus != "" {
		t.Fatalf("未配置导出不该写状态: %q", got.ExportStatus)
	}
}

func TestExport_成功落盘且内容与库内一致(t *testing.T) {
	setupSslExportTestDB(t)
	dir := t.TempDir()
	certFile := filepath.Join(dir, "out", "a.crt")
	keyFile := filepath.Join(dir, "out", "a.key")

	id, certPEM, keyPEM := addSslConfigForExport(t, "ok.example.com", certFile, keyFile)
	// AddApi 已经不导出，导出由调用方触发
	msg, err := WafSslConfigServiceApp.ExportById(id)
	if err != nil {
		t.Fatalf("导出失败: %v", err)
	}
	if !strings.Contains(msg, "导出成功") {
		t.Fatalf("导出提示不对: %q", msg)
	}

	gotCert, err := os.ReadFile(certFile)
	if err != nil || string(gotCert) != certPEM {
		t.Fatalf("导出的证书内容不对: err=%v", err)
	}
	gotKey, err := os.ReadFile(keyFile)
	if err != nil || string(gotKey) != keyPEM {
		t.Fatalf("导出的私钥内容不对: err=%v", err)
	}

	// 状态要回写，前端才能看到"上次导出成功没有"
	got := WafSslConfigServiceApp.GetDetailInner(id)
	if !strings.Contains(got.ExportStatus, "导出成功") {
		t.Fatalf("导出状态未回写: %q", got.ExportStatus)
	}
}

func TestExport_续期换证后文件跟着更新(t *testing.T) {
	db := setupSslExportTestDB(t)
	dir := t.TempDir()
	certFile := filepath.Join(dir, "a.crt")
	keyFile := filepath.Join(dir, "a.key")

	id, _, _ := addSslConfigForExport(t, "renew.example.com", certFile, keyFile)
	if _, err := WafSslConfigServiceApp.ExportById(id); err != nil {
		t.Fatalf("首次导出失败: %v", err)
	}

	// 模拟续期：证书夹内容被换成新证书（ACME 路径走的就是 ModifyInner）
	newCert, newKey := genExportTestCert(t, "renew.example.com")
	cfg := WafSslConfigServiceApp.GetDetailInner(id)
	if err := cfg.FillByCertAndKey(newCert, newKey); err != nil {
		t.Fatalf("填充新证书失败: %v", err)
	}
	if err := WafSslConfigServiceApp.ModifyInner(cfg); err != nil {
		t.Fatalf("更新证书夹失败: %v", err)
	}
	// ModifyInner 的 beanMap 不含导出列，导出配置必须还在（否则续期后就再也不导出了）
	var afterModify model.SslConfig
	if err := db.Where("id = ?", id).First(&afterModify).Error; err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if afterModify.ExportCertPath != certFile || afterModify.ExportKeyPath != keyFile {
		t.Fatalf("更新证书内容后导出配置丢了: %+v", afterModify)
	}

	if _, err := WafSslConfigServiceApp.ExportById(id); err != nil {
		t.Fatalf("续期后导出失败: %v", err)
	}
	gotCert, _ := os.ReadFile(certFile)
	if string(gotCert) != newCert {
		t.Fatal("续期后磁盘上的证书没有跟着更新")
	}
	gotKey, _ := os.ReadFile(keyFile)
	if string(gotKey) != newKey {
		t.Fatal("续期后磁盘上的私钥没有跟着更新")
	}
}

func TestExport_坏路径只报错不写文件(t *testing.T) {
	setupSslExportTestDB(t)
	dir := t.TempDir()
	okKey := filepath.Join(dir, "a.key")

	cases := []struct {
		name       string
		exportCert string
		exportKey  string
	}{
		{"只填了证书路径", filepath.Join(dir, "a.crt"), ""},
		{"只填了密钥路径", "", okKey},
		{"相对路径", "certs/a.crt", "certs/a.key"},
		{"两个路径相同", filepath.Join(dir, "same.pem"), filepath.Join(dir, "same.pem")},
		{"路径含换行", filepath.Join(dir, "a\n.crt"), okKey},
		{"以分隔符结尾", dir + string(filepath.Separator), okKey},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// 证书里的域名只能是 ASCII，所以用序号而不是中文用例名
			id, _, _ := addSslConfigForExport(t, fmt.Sprintf("bad%d.example.com", i), c.exportCert, c.exportKey)
			msg, err := WafSslConfigServiceApp.ExportById(id)
			if err == nil {
				t.Fatalf("坏路径应报错，实际返回 msg=%q", msg)
			}
			// 失败原因要落到状态列，用户在页面上能看见
			got := WafSslConfigServiceApp.GetDetailInner(id)
			if !strings.Contains(got.ExportStatus, "失败") {
				t.Fatalf("失败原因未回写状态: %q", got.ExportStatus)
			}
			// 证书本身必须完好——导出失败不能反过来动库里的证书
			if got.CertContent == "" || got.SerialNo == "" {
				t.Fatalf("导出失败影响了证书本身: %+v", got)
			}
		})
	}
}

func TestExport_目录不可写时报错且不影响库内证书(t *testing.T) {
	setupSslExportTestDB(t)
	dir := t.TempDir()
	// 用普通文件当父目录，模拟"路径权限有问题/目录建不出来"
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatalf("建文件失败: %v", err)
	}

	id, certPEM, _ := addSslConfigForExport(t, "denied.example.com",
		filepath.Join(blocker, "sub", "a.crt"), filepath.Join(blocker, "sub", "a.key"))

	if _, err := WafSslConfigServiceApp.ExportById(id); err == nil {
		t.Fatal("目录建不出来时应报错")
	}
	got := WafSslConfigServiceApp.GetDetailInner(id)
	if got.CertContent != certPEM {
		t.Fatal("导出失败不应影响库内证书内容")
	}
	if !strings.Contains(got.ExportStatus, "失败") {
		t.Fatalf("失败原因未回写状态: %q", got.ExportStatus)
	}
}

func TestExport_不能覆盖自己的自动加载路径(t *testing.T) {
	setupSslExportTestDB(t)
	dir := t.TempDir()
	loadCert := filepath.Join(dir, "load.crt")
	loadKey := filepath.Join(dir, "load.key")
	// 用户放在加载路径上的源文件
	if err := os.WriteFile(loadCert, []byte("user-origin-cert"), 0o644); err != nil {
		t.Fatalf("建文件失败: %v", err)
	}

	certPEM, keyPEM := genExportTestCert(t, "selfload.example.com")
	id, err := WafSslConfigServiceApp.AddApi(request.SslConfigAddReq{
		CertContent: certPEM, KeyContent: keyPEM,
		CertPath: loadCert, KeyPath: loadKey,
		ExportCertPath: loadCert, ExportKeyPath: loadKey,
	})
	if err != nil {
		t.Fatalf("新增失败: %v", err)
	}

	if _, err = WafSslConfigServiceApp.ExportById(id); err == nil {
		t.Fatal("导出路径等于自动加载路径时应拒绝")
	}
	got, _ := os.ReadFile(loadCert)
	if string(got) != "user-origin-cert" {
		t.Fatalf("用户放在加载路径上的源文件被反向覆盖了: %q", got)
	}
}

func TestExport_不能抢占其它证书夹的路径(t *testing.T) {
	setupSslExportTestDB(t)
	dir := t.TempDir()
	occupied := filepath.Join(dir, "shared.crt")
	occupiedKey := filepath.Join(dir, "shared.key")

	firstId, _, _ := addSslConfigForExport(t, "first.example.com", occupied, occupiedKey)
	if _, err := WafSslConfigServiceApp.ExportById(firstId); err != nil {
		t.Fatalf("第一个证书夹导出失败: %v", err)
	}
	firstContent, _ := os.ReadFile(occupied)

	// 第二个证书夹填了同样的导出路径
	secondId, _, _ := addSslConfigForExport(t, "second.example.com", occupied, occupiedKey)
	if _, err := WafSslConfigServiceApp.ExportById(secondId); err == nil {
		t.Fatal("和其它证书夹导出路径撞车时应拒绝")
	}
	afterContent, _ := os.ReadFile(occupied)
	if string(afterContent) != string(firstContent) {
		t.Fatal("第一个证书夹导出的文件被第二个覆盖了")
	}
}

func TestExport_备份条目不继承导出配置(t *testing.T) {
	setupSslExportTestDB(t)
	dir := t.TempDir()
	certFile := filepath.Join(dir, "a.crt")
	keyFile := filepath.Join(dir, "a.key")

	id, _, _ := addSslConfigForExport(t, "backup.example.com", certFile, keyFile)
	origin := WafSslConfigServiceApp.GetDetailInner(id)

	// 续期时会先把旧证书备份一份，备份条目不能带着导出路径，
	// 否则以后编辑这条备份就会把旧证书写回去，覆盖掉新证书
	WafSslConfigServiceApp.CreateNewIdInner(origin)

	var all []model.SslConfig
	if err := global.GWAF_LOCAL_DB.Find(&all).Error; err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	for _, c := range all {
		if c.Id == id {
			continue
		}
		if c.ExportCertPath != "" || c.ExportKeyPath != "" || c.ExportStatus != "" {
			t.Fatalf("备份条目继承了导出配置: %+v", c)
		}
	}
}

func TestExport_证书内容为空时不写空文件(t *testing.T) {
	setupSslExportTestDB(t)
	dir := t.TempDir()
	certFile := filepath.Join(dir, "empty.crt")
	keyFile := filepath.Join(dir, "empty.key")

	// 直接造一条内容为空的记录（模拟异常数据）
	cfg := model.SslConfig{ExportCertPath: certFile, ExportKeyPath: keyFile}
	cfg.Id = "empty-content-id"
	cfg.USER_CODE, cfg.Tenant_ID = global.GWAF_USER_CODE, global.GWAF_TENANT_ID
	if err := global.GWAF_LOCAL_DB.Create(&cfg).Error; err != nil {
		t.Fatalf("造数据失败: %v", err)
	}

	if _, err := WafSslConfigServiceApp.ExportById(cfg.Id); err == nil {
		t.Fatal("证书内容为空时应报错")
	}
	if _, err := os.Stat(certFile); !os.IsNotExist(err) {
		t.Fatal("证书内容为空时不该产生文件")
	}
}

func TestExport_证书夹不存在时报错不panic(t *testing.T) {
	setupSslExportTestDB(t)
	if _, err := WafSslConfigServiceApp.ExportById("not-exist-id"); err == nil {
		t.Fatal("证书夹不存在时应报错")
	}
	if _, err := WafSslConfigServiceApp.ExportById(""); err == nil {
		t.Fatal("ID为空时应报错")
	}
}

func TestExport_编辑接口不传导出字段时保持原值(t *testing.T) {
	setupSslExportTestDB(t)
	dir := t.TempDir()
	certFile := filepath.Join(dir, "a.crt")
	keyFile := filepath.Join(dir, "a.key")

	id, _, _ := addSslConfigForExport(t, "keep.example.com", certFile, keyFile)

	// 老前端不认识 export_* 字段，传 nil，此时不能把用户已配好的导出路径清空
	newCert, newKey := genExportTestCert(t, "keep2.example.com")
	if err := WafSslConfigServiceApp.ModifyApi(request.SslConfigEditReq{
		Id: id, CertContent: newCert, KeyContent: newKey,
	}); err != nil {
		t.Fatalf("编辑失败: %v", err)
	}
	got := WafSslConfigServiceApp.GetDetailInner(id)
	if got.ExportCertPath != certFile || got.ExportKeyPath != keyFile {
		t.Fatalf("旧前端编辑后导出配置被清空了: %+v", got)
	}

	// 显式传空串则是用户主动关闭导出
	empty := ""
	if err := WafSslConfigServiceApp.ModifyApi(request.SslConfigEditReq{
		Id: id, CertContent: newCert, KeyContent: newKey,
		ExportCertPath: &empty, ExportKeyPath: &empty,
	}); err != nil {
		t.Fatalf("编辑失败: %v", err)
	}
	got = WafSslConfigServiceApp.GetDetailInner(id)
	if got.ExportCertPath != "" || got.ExportKeyPath != "" {
		t.Fatalf("显式传空串应关闭导出: %+v", got)
	}
}
