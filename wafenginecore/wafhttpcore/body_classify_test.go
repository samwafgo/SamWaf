package wafhttpcore

import (
	"bytes"
	"testing"
)

func TestIsConfirmedBinaryBody(t *testing.T) {
	realJPEG := append([]byte{
		0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00, 0x01, 0x01, 0x00, 0x00, 0x01,
		0x00, 0x01, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43, 0x00,
	}, []byte{0x1c, 0x16, 0x16, 0x20, 0x2c, 0x20, 0x23, 0x26, 0x27, 0x29, 0x2a, 0x29, 0x19, 0x1f, 0x2d, 0x30}...)

	realPNG := []byte{
		0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A,
		0x00, 0x00, 0x00, 0x0D, 'I', 'H', 'D', 'R',
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, 0xDE,
	}

	realProtobuf := []byte{0x08, 0x96, 0x01, 0x12, 0x04, 0x00, 0x01, 0x02, 0x03, 0x1A, 0x02, 0xFF, 0xFE}

	tests := []struct {
		name        string
		contentType string
		body        []byte
		want        bool
	}{
		{"真实JPEG配image/jpeg", "image/jpeg", realJPEG, true},
		{"真实PNG改名jpg配image/jpeg", "image/jpeg", realPNG, true},
		{"真实PNG配octet-stream", "application/octet-stream", realPNG, true},
		{"真实Protobuf配grpc", "application/grpc+proto", realProtobuf, true},
		{"SVG虽属image但为XML文本必须拒绝", "image/svg+xml", append([]byte("<svg onload=alert(1)>"), bytes.Repeat([]byte{0x00}, 20)...), false},
		{"伪造image/jpeg传JSON注入必须拒绝", "image/jpeg", []byte(`{"id":"1' UNION SELECT username,password FROM users--"}`), false},
		{"伪造image/gif加GIF89a纯文本多态SQLi必须拒绝", "image/gif", []byte("GIF89a' UNION SELECT username,password FROM users--"), false},
		{"伪造image/jpeg加4字节魔数头夹带长SQLi必须拒绝", "image/jpeg", append([]byte{0xFF, 0xD8, 0xFF, 0x00}, []byte("' UNION SELECT username,password FROM users WHERE '1'='1--")...), false},
		{"urlencoded夹带NUL字节绝不判为二进制", "application/x-www-form-urlencoded", append(bytes.Repeat([]byte{0x00}, 20), []byte("&id=1' OR '1'='1")...), false},
		{"GBK中文文本伪装octet-stream不判为二进制", "application/octet-stream", []byte{0xC4, 0xE3, 0xBA, 0xC3, 0xCA, 0xC0, 0xBD, 0xE7, '1', '\'', ' ', 'O', 'R', ' ', '1', '=', '1'}, false},
		{"[M2]0x7F合法JSON字符多态包绝不判为二进制", "application/octet-stream", []byte("{\"pad\":\"" + string(bytes.Repeat([]byte{0x7F}, 64)) + "\",\"q\":\"1' UNION SELECT 1,2--\"}"), false},
		{"[M2]声称image/jpeg却无FFD8FF魔数绝不判为二进制", "image/jpeg", append(bytes.Repeat([]byte{0x00, 0x01}, 300), []byte("1' UNION SELECT 1,2--")...), false},
		{"[M2]前5KB二进制后接5KB纯ASCII注入载荷绝不判为二进制", "application/octet-stream", append(bytes.Repeat([]byte{0x00, 0xFF, 0x01, 0x89}, 1280), bytes.Repeat([]byte("1' UNION SELECT username,password FROM users-- "), 110)...), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsConfirmedBinaryBody(tc.contentType, tc.body); got != tc.want {
				t.Fatalf("IsConfirmedBinaryBody(%q) = %v, 期望 %v", tc.contentType, got, tc.want)
			}
		})
	}
}
