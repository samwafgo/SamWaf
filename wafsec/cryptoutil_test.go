package wafsec

import (
	"fmt"
	"io/ioutil"
	"testing"
)

func TestCryptoUtil_CreateKeys(t *testing.T) {
	//生成密钥对
	crsa := CryptoUtil{}

	//rsa 密钥文件产生
	fmt.Println("-------------------------------获取RSA公私钥-----------------------------------------")
	prvKey, pubKey := crsa.CreateKeys(4096)
	fmt.Println(string(prvKey))
	fmt.Println(string(pubKey))

	// 保存私钥和公钥到文件
	err := ioutil.WriteFile("private_key.pem", prvKey, 0600)
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile("public_key.pem", pubKey, 0600)
	if err != nil {
		panic(err)
	}

	pubKey, _ = crsa.File2Bytes("public_key.pem")
	prvKey, _ = crsa.File2Bytes("private_key.pem")
}
