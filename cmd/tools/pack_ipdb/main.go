// pack_ipdb 把 ip2region 数据文件打成升级包，供 SamWaf 客户端在线下载。
//
// 背景：GeoLite2 受 MaxMind 再分发授权限制已从二进制中去内嵌，IPv6 改用 ip2region_v6.xdb；
//
// 用法：
//
//	go run ./cmd/tools/pack_ipdb [flags]
//
// Flags：
//
//	-version   string  版本号，建议用数据日期，格式 YYYY.MM.DD（默认取当天）
//	-changelog string  本次更新说明（默认 ""）
//	-source    string  ip2region 数据文件所在目录（需含 ip2region_v6.xdb / ip2region.xdb）
//	-output    string  输出目录（默认 release/web/ipdb-dataset）
//	-base-url  string  下载基础 URL（默认 https://update.samwaf.com）
//
// 输出：
//
//	<output>/<version>/ip2region_v6.xdb   数据文件副本
//	<output>/<version>/ip2region.xdb
//	<output>/latest.json                  升级清单
//
// latest.json 结构：
//
//	{
//	  "version": "2026.08.11",
//	  "changelog": "...",
//	  "files": {
//	    "ip2region_v6": {"url": "https://update.samwaf.com/ipdb-dataset/2026.08.11/ip2region_v6.xdb",
//	                     "sha256": "...", "size": 36700160}
//	  }
//	}
//
// 数据来源（Apache-2.0，转发分发时需随包附上游 LICENSE 与署名）：
//
//	https://gitee.com/lionsoul/ip2region/tree/master/data
//	https://github.com/lionsoul2014/ip2region/tree/master/data
package main

import (
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

// packItem 一个待打包的数据文件：key 必须与 iplocation.SupportedDownloads 里的 Key 一致。
type packItem struct {
	Key      string
	FileName string
}

var items = []packItem{
	{Key: "ip2region_v6", FileName: "ip2region_v6.xdb"},
	{Key: "ip2region_v4", FileName: "ip2region.xdb"},
}

type remoteFile struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type manifest struct {
	Version   string                `json:"version"`
	Changelog string                `json:"changelog"`
	Files     map[string]remoteFile `json:"files"`
}

func main() {
	var (
		version   = flag.String("version", time.Now().Format("2006.01.02"), "版本号，建议用数据日期 YYYY.MM.DD")
		changelog = flag.String("changelog", "", "本次更新说明")
		source    = flag.String("source", "data", "ip2region 数据文件所在目录")
		output    = flag.String("output", filepath.Join("release", "web", "ipdb-dataset"), "输出目录")
		baseURL   = flag.String("base-url", "https://update.samwaf.com", "下载基础 URL")
	)
	flag.Parse()

	verDir := filepath.Join(*output, *version)
	if err := os.MkdirAll(verDir, 0o755); err != nil {
		fatal("创建输出目录失败: %v", err)
	}

	m := manifest{Version: *version, Changelog: *changelog, Files: map[string]remoteFile{}}
	packed := 0
	for _, it := range items {
		src := filepath.Join(*source, it.FileName)
		st, err := os.Stat(src)
		if err != nil {
			// 允许只打其中一个文件：IPv4 库仍随程序内置，通常不需要每次都发
			fmt.Printf("跳过 %s（未找到 %s）\n", it.Key, src)
			continue
		}
		dst := filepath.Join(verDir, it.FileName)
		if err = copyFile(src, dst); err != nil {
			fatal("复制 %s 失败: %v", it.FileName, err)
		}
		sum, err := fileSHA256(dst)
		if err != nil {
			fatal("计算 %s 校验和失败: %v", it.FileName, err)
		}
		m.Files[it.Key] = remoteFile{
			URL:    fmt.Sprintf("%s/ipdb-dataset/%s/%s", strings.TrimRight(*baseURL, "/"), *version, it.FileName),
			SHA256: sum,
			Size:   st.Size(),
		}
		packed++
		fmt.Printf("已打包 %-16s %10d 字节  sha256=%s\n", it.FileName, st.Size(), sum)
	}
	if packed == 0 {
		fatal("没有任何可打包的文件，请检查 -source=%s", *source)
	}

	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		fatal("序列化清单失败: %v", err)
	}
	manifestPath := filepath.Join(*output, "latest.json")
	if err = os.WriteFile(manifestPath, b, 0o644); err != nil {
		fatal("写清单失败: %v", err)
	}
	fmt.Printf("\n清单已生成: %s\n版本: %s\n", manifestPath, *version)
	fmt.Println("提醒：上架时请把 ip2region 上游的 LICENSE 与署名一并放到 ipdb-dataset/ 目录下。")
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func fatal(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}
