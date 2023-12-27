package wafsec

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

// AesEncrypt data为明文  key为密钥
func AesEncrypt(data, key []byte) string {
	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}
	blockSize := block.BlockSize()
	padding := blockSize - len(data)%blockSize
	text := bytes.Repeat([]byte{byte(padding)}, padding)
	data = append(data, text...)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypt := make([]byte, len(data))
	blockMode.CryptBlocks(crypt, data)
	return base64.StdEncoding.EncodeToString(crypt)
}

// AesDecrypt 使用AES解密算法对数据进行解密
func AesDecrypt(data, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	blockSize := block.BlockSize()
	if len(data) < blockSize {
		return nil
	}
	iv := key[:blockSize] // 选择密钥的前blockSize字节作为IV
	blockMode := cipher.NewCBCDecrypter(block, iv)
	decryptedData := make([]byte, len(data))
	blockMode.CryptBlocks(decryptedData, data)

	// 去除填充
	padding := int(decryptedData[len(decryptedData)-1])
	return decryptedData[:len(decryptedData)-padding]
}
