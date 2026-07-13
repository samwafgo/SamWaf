package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/utils"
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"errors"
	"fmt"
	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/net/html/charset"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"
)

// encodingDetectPeekSize 编码自动检测的探测窗口大小（meta声明可能在1024字节之后）
const encodingDetectPeekSize = 8192

// rawLatin1Charset 内部无损兜底编码名：真正的ISO-8859-1（256字节全双射，解码→处理→回写字节级无损）
// 不能直接用"iso-8859-1"标签——WHATWG会把它归一到windows-1252，而windows-1252有5个
// 未定义字节（0x81/0x8D/0x8F/0x90/0x9D）解码会变成U+FFFD，做不到无损往返
const rawLatin1Charset = "x-raw-latin1"

// resolveCharset 将任意charset名称解析为编码，支持全部WHATWG标准编码（约40种、200+别名）
// 返回编码实例和规范名；无法识别、auto、或映射到replacement伪编码时返回nil
func resolveCharset(name string) (encoding.Encoding, string) {
	name = strings.Trim(strings.TrimSpace(name), `"'`)
	if name == "" || strings.EqualFold(name, "auto") {
		return nil, ""
	}
	if strings.EqualFold(name, rawLatin1Charset) {
		return charmap.ISO8859_1, rawLatin1Charset
	}
	// 用htmlindex取原始编码而非charset.Lookup：后者返回的编码器自带HTML转义包装，
	// 不可编码字符会变成&#NNN;（对JSON/JS响应会破坏语法），原始编码器才能配合ReplaceUnsupported
	enc, lookupErr := htmlindex.Get(name)
	if lookupErr != nil {
		return nil, ""
	}
	canonical, nameErr := htmlindex.Name(enc)
	// replacement伪编码（hz-gb-2312/iso-2022-cn等危险标签）解码会把整个body变成U+FFFD，不能使用
	if nameErr != nil || canonical == "replacement" {
		return nil, ""
	}
	return enc, canonical
}

// charsetFromContentType 从Content-Type头中提取charset值，未指定时返回空
func charsetFromContentType(contentType string) string {
	for _, part := range strings.Split(contentType, ";") {
		part = strings.TrimSpace(part)
		if len(part) > 8 && strings.EqualFold(part[:8], "charset=") {
			return strings.Trim(part[8:], `"'`)
		}
	}
	return ""
}

// charsetFromHTMLHead 在HTML头部内容中扫描charset声明或DOCTYPE，返回解析出的编码
// 作为DetermineEncoding（只预扫描前1024字节）的扩窗补充
func charsetFromHTMLHead(htmlHead string) (encoding.Encoding, string) {
	if idx := strings.Index(strings.ToLower(htmlHead), "charset="); idx != -1 {
		substr := strings.TrimLeft(htmlHead[idx+8:], "\"' ")
		end := len(substr)
		for i, c := range substr {
			if !(c == '-' || c == '_' || c == ':' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
				end = i
				break
			}
		}
		if enc, canonical := resolveCharset(substr[:end]); enc != nil {
			return enc, canonical
		}
	}
	// XHTML 1.0 通常默认utf-8
	if strings.Contains(htmlHead, "xhtml1-transitional.dtd") {
		return resolveCharset("utf-8")
	}
	return nil, ""
}

// validUTF8Prefix 判断字节序列是否为合法UTF-8（容忍末尾被探测窗口截断的多字节字符）
func validUTF8Prefix(b []byte) bool {
	for trim := 0; trim < utf8.UTFMax; trim++ {
		if utf8.Valid(b) {
			return true
		}
		if len(b) == 0 || b[len(b)-1] < 0x80 {
			return false
		}
		b = b[:len(b)-1]
	}
	return false
}

// looksLikeGBK 无声明时的GBK启发式探测。
// 西欧latin-1文本中"高位字节+ASCII字母"恰好也是合法GBK双字节（如é=0xE9后跟't'），
// 为避免误判，要求所有双字节序列的尾字节也是高位字节（GB2312常用汉字尾字节均≥0xA1），
// 且至少出现2对；宁可放弃判定走无损兜底，也不错误转码
func looksLikeGBK(b []byte) bool {
	highPairs := 0
	for i := 0; i < len(b); {
		c := b[i]
		if c < 0x80 {
			i++
			continue
		}
		if c == 0x80 || c == 0xFF {
			// 非法GBK首字节
			return false
		}
		if i+1 >= len(b) {
			// 末尾被探测窗口截断半个双字节字符，容忍
			break
		}
		trail := b[i+1]
		if trail < 0xA1 || trail == 0xFF {
			// 尾字节非高位（GBK扩展区）或非法：西欧文本特征，放弃GBK判定
			return false
		}
		highPairs++
		i += 2
	}
	if highPairs < 2 {
		return false
	}
	if gbkDecodesClean(b) {
		return true
	}
	// 末尾可能被探测窗口截断半个双字节字符，剪掉最后一个字节再试
	return b[len(b)-1] >= 0x80 && gbkDecodesClean(b[:len(b)-1])
}

func gbkDecodesClean(b []byte) bool {
	decoded, err := simplifiedchinese.GBK.NewDecoder().Bytes(b)
	if err != nil {
		return false
	}
	return !bytes.ContainsRune(decoded, utf8.RuneError)
}

// 返回内容前依据情况进行返回压缩数据
func (waf *WafEngine) compressContent(res *http.Response, isStaticAssist bool, inputBytes []byte, encodeType string) (respBytes []byte, err error) {

	// 如果是静态资源响应或资源类型请求，直接返回原始内容
	if isStaticAssist {
		return inputBytes, errors.New("静态资源或资源类型请求，跳过编码转换")
	}

	// 优先使用检测阶段返回的编码，否则从Content-Type头提取
	charsetName := encodeType
	if charsetName == "" {
		charsetName = charsetFromContentType(res.Header.Get("Content-Type"))
	}

	encodedBytes := inputBytes
	// 内容在处理阶段是UTF-8，回写前需要编码回原始字符集
	if charsetName != "" && !strings.EqualFold(charsetName, "utf-8") && !strings.EqualFold(charsetName, "utf8") {
		if enc, canonical := resolveCharset(charsetName); enc != nil {
			// ReplaceUnsupported：目标字符集无法表示的字符替换为占位符而非报错中断
			converted, encodeErr := encoding.ReplaceUnsupported(enc.NewEncoder()).Bytes(inputBytes)
			if encodeErr != nil {
				zlog.Warn("编码转换失败(UTF-8 -> %s): %v", canonical, encodeErr)
				// 转换失败时使用原始UTF-8内容
			} else {
				encodedBytes = converted
			}
		} else {
			zlog.Debug("不支持的字符集编码转换: %s，保持UTF-8编码", charsetName)
		}
	}

	// 根据Content-Encoding进行压缩
	switch res.Header.Get("Content-Encoding") {
	case "gzip":
		respBytes, err = utils.GZipEncode(encodedBytes)
	case "deflate":
		respBytes, err = utils.DeflateEncode(encodedBytes)
	case "br":
		respBytes, err = utils.BrotliEncode(encodedBytes)
	case "zstd":
		respBytes, err = utils.ZstdEncode(encodedBytes)
	default:
		respBytes = encodedBytes
	}
	return
}

// 获取原始内容
func (waf *WafEngine) getOrgContent(resp *http.Response, isStaticAssist bool, defaultEncoding string) (cntBytes []byte, encodeType string, err error) {
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return bodyBytes, "", fmt.Errorf("读取原始响应体失败: %v", err)
	}
	// 重新设置响应体，以便后续处理
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// 如果是静态资源响应或资源类型请求，直接返回原始内容
	if isStaticAssist {
		return bodyBytes, "", errors.New("静态资源或资源类型请求，跳过编码转换")
	}

	// 根据内容编码处理压缩（从独立reader读取，保持resp.Body完整不被消耗）
	var bodyReader io.Reader
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		gzipReader, gzipErr := gzip.NewReader(bytes.NewReader(bodyBytes))
		if gzipErr != nil {
			zlog.Warn("gzip解压失败: %v", gzipErr)
			// 失败时返回错误
			return bodyBytes, "", fmt.Errorf("gzip解压失败: %v", gzipErr)
		}
		bodyReader = gzipReader
		defer gzipReader.Close()
	case "deflate":
		deflateReader := flate.NewReader(bytes.NewReader(bodyBytes))
		bodyReader = deflateReader
		defer deflateReader.Close()
	case "br":
		bodyReader = brotli.NewReader(bytes.NewReader(bodyBytes))
	case "zstd":
		zstdReader, zstdErr := zstd.NewReader(bytes.NewReader(bodyBytes))
		if zstdErr != nil {
			zlog.Warn("zstd解压失败: %v", zstdErr)
			return bodyBytes, "", fmt.Errorf("zstd解压失败: %v", zstdErr)
		}
		bodyReader = zstdReader
		defer zstdReader.Close()
	default:
		bodyReader = bytes.NewReader(bodyBytes)
	}
	// 创建缓冲读取器
	bufReader := bufio.NewReaderSize(bodyReader, encodingDetectPeekSize)

	contentType := resp.Header.Get("Content-Type")
	var currentEncoding encoding.Encoding
	charsetNameFinal := ""

	// 优先级1：站点配置的默认编码（auto或空表示走自动检测）
	if enc, name := resolveCharset(defaultEncoding); enc != nil {
		currentEncoding = enc
		charsetNameFinal = name
	} else if defaultEncoding != "" && !strings.EqualFold(defaultEncoding, "auto") {
		zlog.Debug("站点默认编码无法识别: %s，转入自动检测", defaultEncoding)
	}

	// 优先级2：Content-Type头中显式指定的字符集
	if currentEncoding == nil {
		if headerCharset := charsetFromContentType(contentType); headerCharset != "" {
			if enc, name := resolveCharset(headerCharset); enc != nil {
				zlog.Debug("从Content-Type中检测到字符集: %s", name)
				currentEncoding = enc
				charsetNameFinal = name
			}
		}
	}

	// 优先级3：自动检测（BOM/meta预扫描 → 扩窗meta扫描 → UTF-8校验 → GBK探测 → windows-1252无损兜底）
	if currentEncoding == nil {
		peekBytes, peekErr := bufReader.Peek(encodingDetectPeekSize)
		if peekErr != nil && peekErr != io.EOF {
			return bodyBytes, "", fmt.Errorf("编码检测错误，Peek失败: %v", peekErr)
		}
		detectedEncoding, name, certain := charset.DetermineEncoding(peekBytes, contentType)
		// certain来自BOM或头部charset；非windows-1252的不确定结果来自WHATWG meta预扫描，同样可信
		// windows-1252是DetermineEncoding找不到任何依据时的默认值，需继续用后续手段甄别
		if name != "replacement" && (certain || name != "windows-1252") {
			zlog.Debug("编码检测结果: %s (certain=%v)", name, certain)
			currentEncoding = detectedEncoding
			charsetNameFinal = name
		}
		if currentEncoding == nil {
			// meta声明可能在1024字节之后，扩大窗口手工扫描
			if enc, name := charsetFromHTMLHead(string(peekBytes)); enc != nil {
				zlog.Debug("通过HTML头部meta/doctype辅助检测到字符集: %s", name)
				currentEncoding = enc
				charsetNameFinal = name
			}
		}
		if currentEncoding == nil && validUTF8Prefix(peekBytes) {
			// 无任何声明但内容是合法UTF-8（含纯ASCII），这是线上最常见的情况
			zlog.Debug("无编码声明，内容通过UTF-8校验，按utf-8处理")
			charsetNameFinal = "utf-8"
			currentEncoding, _ = charset.Lookup("utf-8")
		}
		if currentEncoding == nil && looksLikeGBK(peekBytes) {
			zlog.Debug("无编码声明，GBK探测命中，按gbk处理")
			currentEncoding = simplifiedchinese.GBK
			charsetNameFinal = "gbk"
		}
		if currentEncoding == nil {
			// ISO-8859-1为256字节全双射：解码→处理→回写字节级无损，ASCII部分的替换仍然有效
			zlog.Debug("编码无法确定，使用latin-1无损兜底处理")
			currentEncoding = charmap.ISO8859_1
			charsetNameFinal = rawLatin1Charset
		}
	}

	// UTF-8内容无需转换直接读取，避免个别非法字节被解码器替换为U+FFFD导致内容变动
	if strings.EqualFold(charsetNameFinal, "utf-8") {
		resBodyBytes, readErr := io.ReadAll(bufReader)
		if readErr != nil {
			zlog.Warn("读取响应体失败: %v", readErr)
			return bodyBytes, "", fmt.Errorf("读取响应体失败: %v", readErr)
		}
		return resBodyBytes, "utf-8", nil
	}

	// 使用检测到的编码创建转换读取器
	reader := transform.NewReader(bufReader, currentEncoding.NewDecoder())

	// 读取全部内容
	resBodyBytes, readErr := io.ReadAll(reader)
	if readErr != nil {
		zlog.Warn("读取响应体失败: %v", readErr)
		return bodyBytes, "", fmt.Errorf("读取响应体失败: %v", readErr)
	}

	return resBodyBytes, charsetNameFinal, nil
}

// 处理请求的Content-Encoding解压
func (waf *WafEngine) decompressRequestContent(req *http.Request) ([]byte, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, nil
	}

	// 读取原始请求体
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("读取请求体失败: %v", err)
	}

	// 重新设置请求体
	req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// 根据Content-Encoding进行解压
	var bodyReader io.Reader
	switch req.Header.Get("Content-Encoding") {
	case "gzip":
		gzipReader, gzipErr := gzip.NewReader(bytes.NewReader(bodyBytes))
		if gzipErr != nil {
			zlog.Warn("请求gzip解压失败: %v", gzipErr)
			return bodyBytes, fmt.Errorf("请求gzip解压失败: %v", gzipErr)
		}
		bodyReader = gzipReader
		defer gzipReader.Close()
	case "deflate":
		deflateReader := flate.NewReader(bytes.NewReader(bodyBytes))
		bodyReader = deflateReader
		defer deflateReader.Close()
	case "br":
		brotliReader := brotli.NewReader(bytes.NewReader(bodyBytes))
		bodyReader = brotliReader
	case "zstd":
		zstdReader, zstdErr := zstd.NewReader(bytes.NewReader(bodyBytes))
		if zstdErr != nil {
			zlog.Warn("请求zstd解压失败: %v", zstdErr)
			return bodyBytes, fmt.Errorf("请求zstd解压失败: %v", zstdErr)
		}
		bodyReader = zstdReader
		defer zstdReader.Close()
	default:
		// 没有压缩或不支持的压缩格式，直接返回原始内容
		return bodyBytes, nil
	}

	// 读取解压后的内容
	decompressedBytes, readErr := io.ReadAll(bodyReader)
	if readErr != nil {
		zlog.Warn("读取解压后的请求体失败: %v", readErr)
		return bodyBytes, fmt.Errorf("读取解压后的请求体失败: %v", readErr)
	}

	return decompressedBytes, nil
}
