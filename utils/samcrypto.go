package utils

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func Md5String(str string) string {
	h := md5.New()
	io.WriteString(h, str)
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:])
}

// BcryptHash 用 bcrypt 计算口令哈希（内含随机 per-password 盐，无需单独盐列）。
// bcrypt 仅取口令前 72 字节，过长口令返回错误由上层提示。
func BcryptHash(plain string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// BcryptVerify 校验明文口令是否匹配 bcrypt 哈希。
func BcryptVerify(hash, plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

// IsBcryptHash 判断是否为 bcrypt 哈希串（$2a$/$2b$/$2y$ 前缀），用于区分存量 MD5 与新 bcrypt。
func IsBcryptHash(s string) bool {
	return strings.HasPrefix(s, "$2a$") || strings.HasPrefix(s, "$2b$") || strings.HasPrefix(s, "$2y$")
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
