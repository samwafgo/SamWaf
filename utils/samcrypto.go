package utils

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strings"
)

func Md5String(str string) string {
	h := md5.New()
	io.WriteString(h, str)
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:])
}

// 生成指定长度的密码
func GenerateRandomPassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:',.<>?/`~"

	if length <= 0 {
		return "", fmt.Errorf("密码长度必须大于0")
	}

	var password strings.Builder
	charsetLen := big.NewInt(int64(len(charset)))

	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", err
		}
		password.WriteByte(charset[num.Int64()])
	}

	return password.String(), nil
}
