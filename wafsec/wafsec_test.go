package wafsec

import (
	"fmt"
	"testing"
)

func TestWafSec_EncryptDES3(t *testing.T) {
	wafsec := WafSec{}
	key := "nilihaile"
	plaintext := "https://asdf.com"
	ciphertext := wafsec.Encrypt(key, plaintext)
	decrypted := wafsec.Decrypt(key, ciphertext)
	fmt.Println("Original:", plaintext)
	fmt.Println("Encrypted:", ciphertext)
	fmt.Println("Decrypted:", decrypted)
}
func TestWafSec_DecryptDES3(t *testing.T) {

}
