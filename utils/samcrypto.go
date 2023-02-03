package utils

import (
	"crypto/md5"
	"encoding/hex"
	"io"
)

func Md5String(str string) string {
	h := md5.New()
	io.WriteString(h, str)
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:])
}
