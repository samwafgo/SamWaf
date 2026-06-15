package wafai

import (
	"archive/zip"
	"bytes"
	"testing"
)

// buildTestPackage 构造一个含 manifest + 单模型文件的内存 zip（仅供测试）。
func buildTestPackage(t *testing.T, manifestJSON, modelContent string) []byte {
	t.Helper()
	return buildTestPackageNamed(t, manifestName, manifestJSON, "model_lgbm.txt", modelContent)
}

func buildTestPackageNamed(t *testing.T, manifestEntry, manifestJSON, modelEntry, modelContent string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if w, err := zw.Create(manifestEntry); err == nil {
		_, _ = w.Write([]byte(manifestJSON))
	} else {
		t.Fatal(err)
	}
	if w, err := zw.Create(modelEntry); err == nil {
		_, _ = w.Write([]byte(modelContent))
	} else {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
