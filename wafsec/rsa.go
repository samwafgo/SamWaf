package wafsec

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func GenPublicPrivate() {

	// 生成密钥对
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	publicKey := &privateKey.PublicKey

	// 将私钥转换为PEM格式
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privateKeyPEMBytes := pem.EncodeToMemory(privateKeyPEM)

	// 将公钥转换为PEM格式
	publicKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(publicKey),
	}
	publicKeyPEMBytes := pem.EncodeToMemory(publicKeyPEM)

	// 将PEM格式的密钥转换为Base64编码
	privateKeyBase64 := base64.StdEncoding.EncodeToString(privateKeyPEMBytes)
	publicKeyBase64 := base64.StdEncoding.EncodeToString(publicKeyPEMBytes)

	// 保存私钥和公钥到文件
	err = ioutil.WriteFile("private_key.pem", privateKeyPEMBytes, 0600)
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile("public_key.pem", publicKeyPEMBytes, 0600)
	if err != nil {
		panic(err)
	}

	// 打印Base64编码的私钥和公钥
	fmt.Println("Base64 Encoded Private Key:")
	fmt.Println(privateKeyBase64)
	fmt.Println("Base64 Encoded Public Key:")
	fmt.Println(publicKeyBase64)
}

func EncryptInfo(str string) {
	// 从文件中读取私钥和公钥
	privateKeyPEMBytes, err := ioutil.ReadFile("private_key.pem")
	if err != nil {
		panic(err)
	}
	publicKeyPEMBytes, err := ioutil.ReadFile("public_key.pem")
	if err != nil {
		panic(err)
	}

	// 将Base64编码的私钥和公钥解码回PEM格式
	privateKeyPEM, _ := pem.Decode(privateKeyPEMBytes)
	publicKeyPEM, _ := pem.Decode(publicKeyPEMBytes)

	// 从PEM格式恢复私钥和公钥
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyPEM.Bytes)
	if err != nil {
		panic(err)
	}
	publicKey, err := x509.ParsePKCS1PublicKey(publicKeyPEM.Bytes)
	if err != nil {
		panic(err)
	}

	// 打印恢复的私钥和公钥
	fmt.Println("Restored Private Key:")
	fmt.Println(privateKey)
	fmt.Println("Restored Public Key:")
	fmt.Println(publicKey)

	// 使用公钥加密消息
	message := []byte(str)
	encryptedBytes, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, message, nil)
	if err != nil {
		panic(err)
	}

	fmt.Println("Encrypted message:", encryptedBytes)

	// The first argument is an optional random data generator (the rand.Reader we used before)
	// we can set this value as nil
	// The OEAPOptions in the end signify that we encrypted the data using OEAP, and that we used
	// SHA256 to hash the input.
	decryptedBytes, err := privateKey.Decrypt(nil, encryptedBytes, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		panic(err)
	}

	// We get back the original information in the form of bytes, which we
	// the cast to a string and print
	fmt.Println("decrypted message: ", string(decryptedBytes))
}
