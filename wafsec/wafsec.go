package wafsec

// todo 需要升级go版本: module requires Go 1.20
type WafSec struct {
}

/*
func (wafsec *WafSec) Encrypt(key, plaintext string) string {
	// 加密数据
	cypt := crypto.
		FromString(plaintext).
		SetKey(key).
		Encrypt().
		ToBase64String()
	return cypt
}
func (wafsec *WafSec) Decrypt(key, ciphertext string) string {
	// 解密数据
	cyptde := crypto.
		FromBase64String(ciphertext).
		SetKey(key).
		Decrypt().
		ToString()
	return cyptde
}*/
