package utils

import (
	"bytes"
	"compress/flate"
)

func DeflateEncode(input []byte) ([]byte, error) {
	// 创建一个新的 byte 输出流
	var buf bytes.Buffer
	// 创建一个新的 gzip 输出流
	deflateWriter, err := flate.NewWriter(&buf, flate.DefaultCompression)

	// 将 input byte 数组写入到此输出流中
	_, err = deflateWriter.Write(input)
	if err != nil {
		_ = deflateWriter.Close()
		return nil, err
	}
	if err := deflateWriter.Close(); err != nil {
		return nil, err
	}
	// 返回压缩后的 bytes 数组
	return buf.Bytes(), nil
}
func DeflateDecode(input []byte) ([]byte, error) {
	// 创建一个新的 gzip.Reader
	bytesReader := bytes.NewReader(input)
	flateReader := flate.NewReader(bytesReader)

	defer func() {
		// defer 中关闭 gzipReader
		_ = flateReader.Close()
	}()
	buf := new(bytes.Buffer)
	// 从 Reader 中读取出数据
	if _, err := buf.ReadFrom(flateReader); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
