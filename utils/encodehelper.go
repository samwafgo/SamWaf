package utils

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"github.com/andybalholm/brotli"
)

func BrotliEncode(input []byte) ([]byte, error) {
	// 创建一个新的 byte 输出流
	var buf bytes.Buffer
	// 创建一个新的 brotli 输出流
	brotliWriter := brotli.NewWriter(&buf)
	// 将 input byte 数组写入到此输出流中
	_, err := brotliWriter.Write(input)
	if err != nil {
		_ = brotliWriter.Close()
		return nil, err
	}
	if err := brotliWriter.Close(); err != nil {
		return nil, err
	}
	// 返回压缩后的 bytes 数组
	return buf.Bytes(), nil
}

func BrotliDecode(input []byte) ([]byte, error) {
	// 创建一个新的 brotli.Reader
	bytesReader := bytes.NewReader(input)
	brotliReader := brotli.NewReader(bytesReader)

	buf := new(bytes.Buffer)
	// 从 Reader 中读取出数据
	if _, err := buf.ReadFrom(brotliReader); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

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

func GZipEncode(input []byte) ([]byte, error) {
	// 创建一个新的 byte 输出流
	var buf bytes.Buffer
	// 创建一个新的 gzip 输出流
	gzipWriter := gzip.NewWriter(&buf)
	// 将 input byte 数组写入到此输出流中
	_, err := gzipWriter.Write(input)
	if err != nil {
		_ = gzipWriter.Close()
		return nil, err
	}
	if err := gzipWriter.Close(); err != nil {
		return nil, err
	}
	// 返回压缩后的 bytes 数组
	return buf.Bytes(), nil
}
func GZipDecode(input []byte) ([]byte, error) {
	// 创建一个新的 gzip.Reader
	bytesReader := bytes.NewReader(input)
	gzipReader, err := gzip.NewReader(bytesReader)
	if err != nil {
		return nil, err
	}
	defer func() {
		// defer 中关闭 gzipReader
		_ = gzipReader.Close()
	}()
	buf := new(bytes.Buffer)
	// 从 Reader 中读取出数据
	if _, err := buf.ReadFrom(gzipReader); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
