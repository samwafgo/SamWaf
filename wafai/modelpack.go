package wafai

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
)

const (
	swaiFormatVersion = 1
	manifestName      = "manifest.json"
	maxModelBytes     = 64 * 1024 * 1024 // 单个模型文件解压上限 64MB（防 zip 炸弹）
	maxManifestBytes  = 1 * 1024 * 1024  // manifest 上限 1MB
	maxPackageEntries = 16               // 包内条目数上限
)

// Manifest .swai 模型包元数据（与 SamWafAI export/package.py 对齐）。
type Manifest struct {
	SwaiFormatVersion int     `json:"swai_format_version"`
	ModelVersion      string  `json:"model_version"`
	ModelType         string  `json:"model_type"`
	FeatureVersion    string  `json:"feature_version"`
	FeatureCount      int     `json:"feature_count"`
	ModelFile         string  `json:"model_file"`
	ModelSha256       string  `json:"model_sha256"`
	BlockThreshold    float64 `json:"block_threshold"`
	ObserveThreshold  float64 `json:"observe_threshold"`
	DataFingerprint   string  `json:"data_fingerprint"`
	CreatedAt         string  `json:"created_at"`
}

// loadedPackage 解析后的模型包内容。
type loadedPackage struct {
	Manifest   Manifest
	ModelBytes []byte
}

// loadPackageFile 从磁盘加载并校验 .swai 模型包。
func loadPackageFile(swaiPath string) (*loadedPackage, error) {
	zr, err := zip.OpenReader(swaiPath)
	if err != nil {
		return nil, fmt.Errorf("打开模型包失败: %w", err)
	}
	defer zr.Close()
	return parsePackage(&zr.Reader)
}

// loadPackageBytes 从内存字节加载并校验 .swai 模型包。
func loadPackageBytes(data []byte) (*loadedPackage, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("解析模型包失败: %w", err)
	}
	return parsePackage(zr)
}

func parsePackage(zr *zip.Reader) (*loadedPackage, error) {
	if len(zr.File) > maxPackageEntries {
		return nil, fmt.Errorf("模型包条目过多: %d", len(zr.File))
	}

	var manifestRaw []byte
	files := map[string][]byte{}
	for _, zf := range zr.File {
		// 防路径穿越：条目名必须是简单文件名
		name := zf.Name
		if path.IsAbs(name) || name != path.Clean(name) || containsDotDot(name) {
			return nil, fmt.Errorf("非法的模型包条目名: %q", name)
		}
		limit := int64(maxModelBytes)
		if name == manifestName {
			limit = maxManifestBytes
		}
		data, err := readZipEntry(zf, limit)
		if err != nil {
			return nil, fmt.Errorf("读取条目 %q 失败: %w", name, err)
		}
		if name == manifestName {
			manifestRaw = data
		} else {
			files[name] = data
		}
	}

	if manifestRaw == nil {
		return nil, errors.New("模型包缺少 manifest.json")
	}

	var m Manifest
	if err := json.Unmarshal(manifestRaw, &m); err != nil {
		return nil, fmt.Errorf("解析 manifest 失败: %w", err)
	}

	if m.SwaiFormatVersion != swaiFormatVersion {
		return nil, fmt.Errorf("不支持的模型包格式版本: %d（当前支持 %d）", m.SwaiFormatVersion, swaiFormatVersion)
	}
	// 特征版本硬约束：与 Go 侧不一致则拒绝加载
	if m.FeatureVersion != FeatureVersion {
		return nil, fmt.Errorf("特征版本不匹配: 模型=%s, 引擎=%s（请用匹配版本的 SamWafAI 重新训练）", m.FeatureVersion, FeatureVersion)
	}
	if m.FeatureCount != 0 && m.FeatureCount != FeatureCount {
		return nil, fmt.Errorf("特征维度不匹配: 模型=%d, 引擎=%d", m.FeatureCount, FeatureCount)
	}

	modelBytes, ok := files[m.ModelFile]
	if !ok {
		return nil, fmt.Errorf("模型包缺少模型文件: %q", m.ModelFile)
	}
	// sha256 完整性校验
	if m.ModelSha256 != "" {
		sum := sha256.Sum256(modelBytes)
		if got := hex.EncodeToString(sum[:]); got != m.ModelSha256 {
			return nil, fmt.Errorf("模型文件 sha256 校验失败: 期望 %s 实际 %s", m.ModelSha256, got)
		}
	}

	return &loadedPackage{Manifest: m, ModelBytes: modelBytes}, nil
}

func readZipEntry(zf *zip.File, limit int64) ([]byte, error) {
	rc, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	// 限制读取量防 zip 炸弹：多读 1 字节用于判断是否超限
	data, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("条目解压大小超过上限 %d 字节", limit)
	}
	return data, nil
}

func containsDotDot(p string) bool {
	for i := 0; i+1 < len(p); i++ {
		if p[i] == '.' && p[i+1] == '.' {
			return true
		}
	}
	return false
}
