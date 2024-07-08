package wafsec

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// PKCS7Padding applies PKCS7 padding.
func PKCS7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// PKCS7UnPadding removes PKCS7 padding.
func PKCS7UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("invalid padding size")
	}
	padding := int(data[length-1])
	if padding > length {
		return nil, errors.New("invalid padding size")
	}
	return data[:length-padding], nil
}

// AesEncrypt encrypts data using AES algorithm with the given key.
func AesEncrypt(data, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()
	data = PKCS7Padding(data, blockSize)
	crypt := make([]byte, blockSize+len(data))
	iv := crypt[:blockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	blockMode := cipher.NewCBCEncrypter(block, iv)
	blockMode.CryptBlocks(crypt[blockSize:], data)
	return base64.StdEncoding.EncodeToString(crypt), nil
}

// AesDecrypt decrypts data using AES algorithm with the given key.
func AesDecrypt(data string, key []byte) ([]byte, error) {
	crypt, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	if len(crypt) < blockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := crypt[:blockSize]
	crypt = crypt[blockSize:]
	blockMode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(crypt))
	blockMode.CryptBlocks(decrypted, crypt)
	return PKCS7UnPadding(decrypted)
}
