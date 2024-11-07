package wafhttpcore

import (
	"unicode"
)

// Go 语言版的php URL 解码函数
func phpUrlEncode(str string) string {
	var result []rune   // 用来存储解码后的字符
	data := []rune(str) // 将输入字符串转换为 rune 切片（字符切片）

	for i := 0; i < len(data); i++ {
		if data[i] == '+' {
			// 将 '+' 替换为空格
			result = append(result, ' ')
		} else if data[i] == '%' && i+2 < len(data) && isHexDigit(data[i+1]) && isHexDigit(data[i+2]) {
			// 检查是否为 '%XX' 格式的编码
			// 解析十六进制数
			decoded := hexToInt(data[i+1], data[i+2])
			result = append(result, rune(decoded))
			i += 2 // 跳过已解码的字符
		} else {
			// 其他字符直接添加
			result = append(result, data[i])
		}
	}
	return string(result)
}

// 判断字符是否为十六进制数字
func isHexDigit(c rune) bool {
	return unicode.Is(unicode.ASCII_Hex_Digit, c)
}

// 将两个十六进制字符转换为整数
func hexToInt(a, b rune) int {
	// 将十六进制字符转换为整数
	return int(hexCharToInt(a)*16 + hexCharToInt(b))
}

// 将单个十六进制字符转换为整数
func hexCharToInt(c rune) int {
	switch {
	case '0' <= c && c <= '9':
		return int(c - '0')
	case 'a' <= c && c <= 'f':
		return int(c - 'a' + 10)
	case 'A' <= c && c <= 'F':
		return int(c - 'A' + 10)
	}
	return 0
}
