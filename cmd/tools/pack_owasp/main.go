// pack_owasp 打包 OWASP CRS 规则集为升级包。
//
// 用法：
//
//	go run ./cmd/tools/pack_owasp [flags]
//
// Flags：
//
//	-version   string  版本号，格式 1.0.YYYYMMDD（默认读取 exedata/owasp/version）
//	-changelog string  本次更新说明（默认 ""）
//	-source    string  owasp 数据根目录（默认 cmd/samwaf/exedata/owasp）
//	-output    string  输出目录（默认 release/web/owasp-ruleset）
//	-base-url  string  下载基础 URL（默认 https://update.samwaf.com）
//
// 输出：
//
//	<output>/owasp-<version>.zip    规则包（内含 coreruleset/ + samwaf/ 目录树）
//	<output>/latest.json            升级清单（version / url / sha256 / changelog）
//
// ZIP 内部结构：
//
//	coreruleset/
//	  crs-setup.conf
//	  rules/*.conf
//	samwaf/
//	  before/01-samwaf-init-vars.conf
//	  after/...
//
// 示例：
//
//	go run ./cmd/tools/pack_owasp -version 1.0.20260422 -changelog "升级 CRS 到最新"
package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// packEntry 描述一个要打入 ZIP 的子目录。
// zipBase 是 ZIP 内部顶层目录名（通常与 srcDir 的 Base() 相同）。
type packEntry struct {
	srcDir  string // 要打包的目录绝对路径
	zipBase string // ZIP 内部顶层名称
}

func main() {
	var (
		version   = flag.String("version", "", "版本号，格式 1.0.YYYYMMDD（留空则读取 source/version 文件）")
		changelog = flag.String("changelog", "", "本次更新说明")
		source    = flag.String("source", "", "owasp 数据根目录（留空自动定位到项目内的 exedata/owasp）")
		output    = flag.String("output", "", "输出目录（留空则输出到 release/web/owasp-ruleset）")
		baseURL   = flag.String("base-url", "https://update.samwaf.com", "下载基础 URL，latest.json 中的 url 字段")
	)
	flag.Parse()

	// 自动定位项目根（从工作目录向上找 go.mod）
	projectRoot, err := findProjectRoot()
	if err != nil {
		fatalf("定位项目根失败: %v", err)
	}

	// 解析路径
	if *source == "" {
		*source = filepath.Join(projectRoot, "cmd", "samwaf", "exedata", "owasp")
	}
	if *output == "" {
		*output = filepath.Join(projectRoot, "release", "web", "owasp-ruleset")
	}

	// 读取版本号
	if *version == "" {
		vFile := filepath.Join(*source, "version")
		data, err := os.ReadFile(vFile)
		if err != nil {
			fatalf("读取版本文件失败（%s）: %v", vFile, err)
		}
		*version = strings.TrimSpace(string(data))
	}
	if *version == "" {
		fatalf("-version 不能为空")
	}

	// 确认必须存在的目录
	coreDir := filepath.Join(*source, "coreruleset")
	if _, err := os.Stat(coreDir); err != nil {
		fatalf("coreruleset 目录不存在: %s", coreDir)
	}

	// 构建待打包列表：coreruleset 必选，samwaf 存在时自动加入
	entries := []packEntry{
		{srcDir: coreDir, zipBase: "coreruleset"},
	}
	samwafDir := filepath.Join(*source, "samwaf")
	if st, err := os.Stat(samwafDir); err == nil && st.IsDir() {
		entries = append(entries, packEntry{srcDir: samwafDir, zipBase: "samwaf"})
		fmt.Printf("samwaf 层: %s  ✓\n", samwafDir)
	} else {
		fmt.Printf("samwaf 层: 不存在，跳过（%s）\n", samwafDir)
	}

	// 创建输出目录
	if err := os.MkdirAll(*output, 0755); err != nil {
		fatalf("创建输出目录失败: %v", err)
	}

	zipName := fmt.Sprintf("owasp-%s.zip", *version)
	zipPath := filepath.Join(*output, zipName)

	fmt.Printf("打包版本: %s\n", *version)
	fmt.Printf("输出 ZIP: %s\n", zipPath)

	sha, err := packZip(entries, zipPath)
	if err != nil {
		fatalf("打包失败: %v", err)
	}
	fmt.Printf("SHA256:   %s\n", sha)

	// 写 latest.json
	downloadURL := strings.TrimRight(*baseURL, "/") + "/owasp-ruleset/" + zipName
	manifest := map[string]string{
		"version":   *version,
		"url":       downloadURL,
		"sha256":    sha,
		"changelog": *changelog,
		"built_at":  time.Now().Format(time.RFC3339),
	}
	latestPath := filepath.Join(*output, "latest.json")
	if err := writeJSON(latestPath, manifest); err != nil {
		fatalf("写 latest.json 失败: %v", err)
	}
	fmt.Printf("latest.json: %s\n", latestPath)
	fmt.Println("打包完成。")
}

// packZip 将多个 packEntry 按照各自的 zipBase 打入同一个 ZIP 文件，
// ZIP 内部结构：<zipBase>/<相对路径>
// 返回最终 ZIP 文件的十六进制 SHA256。
func packZip(entries []packEntry, dstZip string) (string, error) {
	f, err := os.Create(dstZip)
	if err != nil {
		return "", err
	}
	defer f.Close()

	w := zip.NewWriter(f)

	for _, entry := range entries {
		// 父目录（用于计算相对路径）
		parentDir := filepath.Dir(entry.srcDir)

		if err := filepath.Walk(entry.srcDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(parentDir, path)
			if err != nil {
				return err
			}
			zipPath := filepath.ToSlash(rel) // 统一正斜杠

			if info.IsDir() {
				// 顶层目录本身不单独写（Walk 会进入其子项）
				if zipPath == entry.zipBase {
					return nil
				}
				_, err = w.Create(zipPath + "/")
				return err
			}
			fw, err := w.Create(zipPath)
			if err != nil {
				return err
			}
			src, err := os.Open(path)
			if err != nil {
				return err
			}
			defer src.Close()
			_, err = io.Copy(fw, src)
			return err
		}); err != nil {
			_ = w.Close()
			return "", fmt.Errorf("打包 %s 失败: %w", entry.zipBase, err)
		}
	}

	if err := w.Close(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}

	return fileSHA256(dstZip)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeJSON(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// findProjectRoot 从当前工作目录向上搜索 go.mod 所在目录。
func findProjectRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("未找到 go.mod，请在项目根目录下运行")
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "错误: "+format+"\n", args...)
	os.Exit(1)
}
