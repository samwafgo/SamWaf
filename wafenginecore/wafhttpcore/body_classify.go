package wafhttpcore

import (
	"bytes"
	"mime"
	"strings"
	"unicode/utf8"
)

const binaryInspectPeekLimit = 4096

var declaredBinaryAppTypes = map[string]struct{}{
	"application/octet-stream":      {},
	"application/pdf":               {},
	"application/zip":               {},
	"application/x-zip-compressed":  {},
	"application/gzip":              {},
	"application/x-gzip":            {},
	"application/x-tar":             {},
	"application/x-bzip2":           {},
	"application/x-xz":              {},
	"application/x-7z-compressed":   {},
	"application/x-rar-compressed":  {},
	"application/vnd.rar":           {},
	"application/zstd":              {},
	"application/wasm":              {},
	"application/protobuf":          {},
	"application/x-protobuf":        {},
	"application/grpc":              {},
	"application/grpc+proto":        {},
	"application/msgpack":           {},
	"application/x-msgpack":         {},
	"application/cbor":              {},
	"application/bson":              {},
	"application/java-archive":      {},
	"application/epub+zip":          {},
	"application/msword":            {},
	"application/vnd.ms-excel":      {},
	"application/vnd.ms-powerpoint": {},
}

// IsConfirmedBinaryBody 多因子校验请求体是否为真实的纯二进制载荷：
//  1. Content-Type 显式声明为二进制媒体类型（排除 image/svg+xml 及一切 +xml/+json/+text 后缀）；
//  2. 首字符不得为 JSON/XML 文本结构起始符（{ / [ / <），且已知格式必须匹配对应文件头魔数；
//  3. 头部窗口、全量字节占比以及尾部窗口（PDF 合法 %%EOF 尾部除外）均须具备真实二进制字节证据（剔除合法 JSON 字符 0x7F），
//     防止通过前缀填充 4KB 二进制字节或 0x7F 多态包夹带明文 SQLi/XSS/RCE 绕过检测。
func IsConfirmedBinaryBody(contentType string, raw []byte) bool {
	if len(raw) == 0 || contentType == "" {
		return false
	}
	mediaType, ok := ParseSingleMediaType(contentType)
	if !ok || !isDeclaredBinaryMediaType(mediaType) {
		return false
	}
	trimmedLead := bytes.TrimLeft(raw, " \t\r\n")
	if len(trimmedLead) == 0 || trimmedLead[0] == '{' || trimmedLead[0] == '[' || trimmedLead[0] == '<' {
		return false
	}
	if !matchesRequiredFormatMagic(mediaType, raw) {
		return false
	}

	head := raw
	if len(head) > binaryInspectPeekLimit {
		head = head[:binaryInspectPeekLimit]
	}
	if !hasBinaryByteEvidence(head) {
		return false
	}
	if len(raw) > binaryInspectPeekLimit {
		// 全量校验：防止 4KB 二进制前缀 + 大段纯 ASCII 注入载荷拼接
		if !hasBinaryByteEvidence(raw) {
			return false
		}
		if !isAllowedPDFTrailer(mediaType, raw) {
			tailSize := binaryInspectPeekLimit
			if len(raw)/2 < tailSize {
				tailSize = len(raw) / 2
			}
			tail := raw[len(raw)-tailSize:]
			if countBinaryIndicatorBytes(tail)*20 < len(tail) {
				return false
			}
		}
	}
	return true
}

// ParseSingleMediaType 严格解析单个 Content-Type 头的主媒体类型；解析失败返回 ("", false)。
func ParseSingleMediaType(contentType string) (string, bool) {
	if strings.TrimSpace(contentType) == "" {
		return "", false
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "", false
	}
	return strings.ToLower(strings.TrimSpace(mediaType)), true
}

// matchesRequiredFormatMagic 对具有固定文件头签名的常见格式强制校验魔数；通用流(如 octet-stream/grpc)不限固定头。
// 对于常见光栅图片类型（不含 SVG），允许匹配任一已确认光栅图片魔数，兼容现实中将 PNG/GIF/WebP 改名为 .jpg 后以 image/jpeg 直传的场景。
func matchesRequiredFormatMagic(mediaType string, raw []byte) bool {
	switch mediaType {
	case "image/jpeg", "image/jpg", "image/png", "image/gif", "image/webp", "image/bmp", "image/x-icon", "image/vnd.microsoft.icon":
		return isConfirmedRasterImageMagic(raw)
	case "application/pdf":
		return bytes.HasPrefix(raw, []byte("%PDF-"))
	case "application/zip", "application/x-zip-compressed", "application/java-archive", "application/epub+zip":
		return bytes.HasPrefix(raw, []byte("PK\x03\x04")) || bytes.HasPrefix(raw, []byte("PK\x05\x06"))
	case "application/gzip", "application/x-gzip":
		return len(raw) >= 2 && raw[0] == 0x1F && raw[1] == 0x8B
	case "application/zstd":
		return bytes.HasPrefix(raw, []byte{0x28, 0xB5, 0x2F, 0xFD})
	case "application/wasm":
		return bytes.HasPrefix(raw, []byte{0x00, 'a', 's', 'm'})
	case "application/x-7z-compressed":
		return bytes.HasPrefix(raw, []byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C})
	case "application/x-rar-compressed", "application/vnd.rar":
		return bytes.HasPrefix(raw, []byte{'R', 'a', 'r', '!', 0x1A, 0x07})
	default:
		if strings.HasPrefix(mediaType, "application/vnd.openxmlformats-officedocument.") ||
			strings.HasPrefix(mediaType, "application/vnd.oasis.opendocument.") {
			return bytes.HasPrefix(raw, []byte("PK\x03\x04"))
		}
		return true
	}
}

func isConfirmedRasterImageMagic(raw []byte) bool {
	return (len(raw) >= 3 && raw[0] == 0xFF && raw[1] == 0xD8 && raw[2] == 0xFF) ||
		bytes.HasPrefix(raw, []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}) ||
		bytes.HasPrefix(raw, []byte("GIF87a")) ||
		bytes.HasPrefix(raw, []byte("GIF89a")) ||
		(len(raw) >= 12 && bytes.HasPrefix(raw, []byte("RIFF")) && bytes.Equal(raw[8:12], []byte("WEBP"))) ||
		bytes.HasPrefix(raw, []byte("BM")) ||
		bytes.HasPrefix(raw, []byte{0x00, 0x00, 0x01, 0x00})
}

func isAllowedPDFTrailer(mediaType string, raw []byte) bool {
	if mediaType != "application/pdf" || !bytes.HasPrefix(raw, []byte("%PDF-")) {
		return false
	}
	tail := raw
	if len(tail) > 1024 {
		tail = tail[len(tail)-1024:]
	}
	return bytes.Contains(tail, []byte("%%EOF"))
}

func isDeclaredBinaryMediaType(mediaType string) bool {
	if mediaType == "" {
		return false
	}
	if strings.HasSuffix(mediaType, "+xml") ||
		strings.HasSuffix(mediaType, "+json") ||
		strings.HasSuffix(mediaType, "+yaml") ||
		strings.HasSuffix(mediaType, "+text") ||
		mediaType == "image/svg" {
		return false
	}
	if strings.HasPrefix(mediaType, "image/") ||
		strings.HasPrefix(mediaType, "audio/") ||
		strings.HasPrefix(mediaType, "video/") ||
		strings.HasPrefix(mediaType, "font/") ||
		strings.HasPrefix(mediaType, "model/") {
		return true
	}
	if _, ok := declaredBinaryAppTypes[mediaType]; ok {
		return true
	}
	return strings.HasPrefix(mediaType, "application/vnd.openxmlformats-officedocument.") ||
		strings.HasPrefix(mediaType, "application/vnd.oasis.opendocument.")
}

// hasBinaryByteEvidence 统计窗口内的 NUL、非空白控制字节（不含 JSON 合法的 0x7F）与非文本编码高位字节占比。
func hasBinaryByteEvidence(peek []byte) bool {
	if len(peek) == 0 {
		return false
	}
	nulCount := 0
	ctrlCount := 0
	for _, b := range peek {
		if b == 0x00 {
			nulCount++
		} else if b < 0x20 && b != '\t' && b != '\n' && b != '\r' {
			ctrlCount++
		}
	}
	invalidUTF8 := countInvalidUTF8Bytes(peek)
	binBytes := nulCount + ctrlCount + invalidUTF8
	if binBytes == 0 {
		return false
	}
	if nulCount > 0 && binBytes*10 >= len(peek) {
		return true
	}
	return binBytes*5 >= len(peek)
}

func countBinaryIndicatorBytes(b []byte) int {
	cnt := 0
	for _, c := range b {
		if c == 0x00 || (c < 0x20 && c != '\t' && c != '\n' && c != '\r') {
			cnt++
		}
	}
	return cnt + countInvalidUTF8Bytes(b)
}

func countInvalidUTF8Bytes(b []byte) int {
	trimmed := b
	for trim := 0; trim < utf8.UTFMax && len(trimmed) > 0; trim++ {
		if utf8.Valid(trimmed) {
			return 0
		}
		if trimmed[len(trimmed)-1] < 0x80 {
			break
		}
		trimmed = trimmed[:len(trimmed)-1]
	}
	if utf8.Valid(trimmed) {
		return 0
	}
	if bytes.IndexByte(trimmed, 0x00) < 0 && looksLikeGBKText(trimmed) {
		return 0
	}
	invalid := 0
	for i := 0; i < len(trimmed); {
		r, width := utf8.DecodeRune(trimmed[i:])
		if r == utf8.RuneError && width == 1 {
			invalid++
		}
		i += width
	}
	return invalid
}

func looksLikeGBKText(b []byte) bool {
	highPairs := 0
	for i := 0; i < len(b); {
		c := b[i]
		if c < 0x80 {
			i++
			continue
		}
		if c == 0x80 || c == 0xFF {
			return false
		}
		if i+1 >= len(b) {
			break
		}
		trail := b[i+1]
		if trail < 0xA1 || trail == 0xFF {
			return false
		}
		highPairs++
		i += 2
	}
	return highPairs >= 2
}
