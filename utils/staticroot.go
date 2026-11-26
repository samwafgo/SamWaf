package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"

	"SamWaf/global"
)

// 静态站点与静态路径路由的目录收口。

// staticSiteDefaultSubDir 内置默认静态目录（相对程序目录），恒允许。
const staticSiteDefaultSubDir = "data/static_site"

// staticSiteBaseDir 取 SamWaf 程序所在目录，单测里可替换。
var staticSiteBaseDir = GetCurrentDir

// staticMaxLinkHops 目录链接链的最大展开跳数，用尽视为无法解析。
var staticMaxLinkHops = 64

// 静态目录判定结果分类，巡检与保存共用。
const (
	StaticRootInvalid    = "invalid"     // 空、含控制字符、不是绝对路径或无法解析
	StaticRootNotAllowed = "not_allowed" // 不在允许目录内
	StaticRootProtected  = "protected"   // 落在程序自身的配置或数据目录
)

// StaticRootError 静态目录不符合策略时的错误，Code 取上面的分类。
type StaticRootError struct {
	Code string
	Msg  string
}

func (e *StaticRootError) Error() string { return e.Msg }

func staticRootErr(code, format string, a ...interface{}) error {
	return &StaticRootError{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// StaticRootErrorCode 取错误分类，非 StaticRootError 返回空串。
func StaticRootErrorCode(err error) string {
	if e, ok := err.(*StaticRootError); ok {
		return e.Code
	}
	return ""
}

func staticSiteAbsBase() string {
	base := staticSiteBaseDir()
	if base == "" {
		return ""
	}
	abs, err := filepath.Abs(base)
	if err != nil {
		return ""
	}
	return filepath.Clean(abs)
}

// StaticSiteDefaultDir 返回内置默认静态目录的绝对路径。
func StaticSiteDefaultDir() string {
	if base := staticSiteAbsBase(); base != "" {
		return filepath.Join(base, staticSiteDefaultSubDir)
	}
	return staticSiteDefaultSubDir
}

// staticSiteAllowedRoots 内置默认目录 + config.yml security.static_site_allowed_dirs。
func staticSiteAllowedRoots() []string {
	roots := make([]string, 0, 4)
	if d := StaticSiteDefaultDir(); filepath.IsAbs(d) {
		roots = append(roots, d)
	}
	for _, d := range strings.Split(global.GCONFIG_STATIC_SITE_ALLOWED_DIRS, ",") {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		cleaned := filepath.Clean(d)
		if !filepath.IsAbs(cleaned) {
			continue
		}
		roots = append(roots, cleaned)
	}
	return roots
}

// staticSiteProtectedRoots 程序自身的配置与数据目录。
func staticSiteProtectedRoots() []string {
	base := staticSiteAbsBase()
	if base == "" {
		return nil
	}
	return []string{filepath.Join(base, "conf"), filepath.Join(base, "data")}
}

// staticSiteProtectedFiles config.yml 自定义的密钥文件位置（可能在程序目录之外）。
// 与 wafsec 打开这些文件的方式一致：相对路径按进程工作目录解析。
func staticSiteProtectedFiles() []string {
	files := make([]string, 0, 2)
	for _, f := range []string{global.GCONFIG_DATA_KEY_FILE, global.GCONFIG_COMM_KEY_FILE} {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if abs, err := filepath.Abs(f); err == nil {
			files = append(files, filepath.Clean(abs))
		}
	}
	return files
}

// samePath 按平台大小写规则比较两个已 Clean 的路径。
func samePath(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// atOrUnder 判断 p 等于 root 或位于 root 之下（均为已 Clean 的路径）。
func atOrUnder(root, p string) bool {
	return samePath(root, p) || pathUnder(root, p)
}

func atOrUnderAny(roots []string, p string) bool {
	for _, root := range roots {
		if atOrUnder(root, p) {
			return true
		}
	}
	return false
}

// ---------------- 路径规范化 ----------------

// stripWindowsDevicePrefix 去掉 \\?\ 与 \\.\ 设备命名空间前缀。
func stripWindowsDevicePrefix(p string) string {
	lower := strings.ToLower(p)
	switch {
	case strings.HasPrefix(lower, `\\?\unc\`):
		return `\\` + p[len(`\\?\unc\`):]
	case strings.HasPrefix(lower, `\\?\`), strings.HasPrefix(lower, `\\.\`):
		return p[4:]
	}
	return p
}

// hasWindowsDevicePrefix 路径是否使用 \\?\ 或 \\.\ 设备命名空间前缀。
func hasWindowsDevicePrefix(p string) bool {
	lower := strings.ToLower(p)
	return strings.HasPrefix(lower, `\\?\`) || strings.HasPrefix(lower, `\\.\`)
}

// staticComparePath 规范用于比较的路径。Windows 下去掉设备前缀并去掉各段末尾的点与空格
// （NTFS 打开路径时会忽略它们）；其他平台只做 Clean。
func staticComparePath(p string) string {
	p = filepath.Clean(p)
	if runtime.GOOS != "windows" {
		return p
	}
	p = stripWindowsDevicePrefix(p)
	vol := filepath.VolumeName(p)
	rest := p[len(vol):]
	sep := string(filepath.Separator)
	parts := strings.Split(rest, sep)
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			continue
		}
		trimmed := strings.TrimRight(part, ". ")
		if trimmed != "" {
			parts[i] = trimmed
		}
	}
	return filepath.Clean(vol + strings.Join(parts, sep))
}

func staticSamePath(a, b string) bool {
	a, b = staticComparePath(a), staticComparePath(b)
	return a == b || samePath(a, b)
}

func staticAtOrUnder(root, p string) bool {
	root, p = staticComparePath(root), staticComparePath(p)
	if root == "" || p == "" {
		return false
	}
	return samePath(root, p) || pathUnder(root, p)
}

func staticAtOrUnderAny(roots []string, p string) bool {
	for _, root := range roots {
		if staticAtOrUnder(root, p) {
			return true
		}
	}
	return false
}

// ---------------- 真实路径解析 ----------------

// expandStaticLinks 逐段展开目录链接后拼回路径。Windows 的 junction 不算软链接，
// 但 os.Readlink 能读到其目标，故按组件尝试展开；读不到目标的组件按字面保留。
// 仅在链接链超过 staticMaxLinkHops 时返回 false。
func expandStaticLinks(p string, hops int) (string, bool) {
	if hops > staticMaxLinkHops {
		return p, false
	}
	vol := filepath.VolumeName(p)
	rest := p[len(vol):]
	sep := string(filepath.Separator)
	cur := vol
	if strings.HasPrefix(rest, sep) {
		cur = vol + sep
		rest = rest[len(sep):]
	}
	if rest == "" || rest == "." {
		return filepath.Clean(p), true
	}
	for _, part := range strings.Split(rest, sep) {
		if part == "" || part == "." {
			continue
		}
		next := filepath.Join(cur, part)
		fi, err := os.Lstat(next)
		if err != nil {
			cur = next
			continue
		}
		if fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			target, lerr := os.Readlink(next)
			if lerr != nil {
				cur = next
				continue
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(cur, target)
			}
			resolved, ok := expandStaticLinks(target, hops+1)
			if !ok {
				return p, false
			}
			cur = resolved
			continue
		}
		cur = next
	}
	return filepath.Clean(cur), true
}

// canonicalizeStaticPath 对路径中最长的已存在前缀取真实规范形式（长名、正确大小写），
// 尚未创建的后缀原样拼回。
func canonicalizeStaticPath(p string) string {
	cand, tail := filepath.Clean(p), ""
	for {
		if real, err := filepath.EvalSymlinks(cand); err == nil {
			if tail == "" {
				return filepath.Clean(real)
			}
			return filepath.Clean(filepath.Join(real, tail))
		}
		parent := filepath.Dir(cand)
		if parent == cand {
			break
		}
		tail = filepath.Join(filepath.Base(cand), tail)
		cand = parent
	}
	return filepath.Clean(p)
}

// resolveStaticRealPath 返回 p 的真实绝对路径。非 Windows 优先用 EvalSymlinks；
// Windows 上 junction 不被 EvalSymlinks 识别，故逐段展开。返回 false 表示路径无法解析
// （链接链过长），调用方应按不可信处理。
func resolveStaticRealPath(p string) (string, bool) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p), false
	}
	abs = filepath.Clean(abs)
	if runtime.GOOS != "windows" {
		if real, err := filepath.EvalSymlinks(abs); err == nil {
			return filepath.Clean(real), true
		}
	}
	expanded, ok := expandStaticLinks(abs, 0)
	if !ok {
		return abs, false
	}
	return canonicalizeStaticPath(expanded), true
}

// realRoots 把根目录解析为真实路径，解析失败时按字面路径。
func realRoots(roots []string) []string {
	out, _ := realRootsChecked(roots)
	return out
}

// realRootsChecked 同上，并报告是否全部解析成功。
func realRootsChecked(roots []string) ([]string, bool) {
	out := make([]string, 0, len(roots))
	allOK := true
	for _, root := range roots {
		real, ok := resolveStaticRealPath(root)
		if !ok {
			allOK = false
		}
		out = append(out, filepath.Clean(real))
	}
	return out, allOK
}

// isProtectedStaticPath 路径落在程序自身的配置/数据目录（内置默认静态目录除外）或是自定义密钥文件。
func isProtectedStaticPath(p string, protected, defaults, files []string) bool {
	for _, f := range files {
		if staticSamePath(f, p) {
			return true
		}
	}
	return staticAtOrUnderAny(protected, p) && !staticAtOrUnderAny(defaults, p)
}

// ValidateStaticRoot 校验静态目录是否允许保存，返回规范化后的绝对路径。
//  1. 非空、无控制字符、必须是绝对路径，且不使用 Windows 设备命名空间前缀；
//  2. Clean 后位于允许目录内（等于允许目录本身也可以）；
//  3. 不得落在程序自身的配置或数据目录（内置默认静态目录除外）；
//  4. 按真实路径再判一次 2、3，目录尚不存在时按已存在祖先的真实路径加后缀判断。
func ValidateStaticRoot(raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "", staticRootErr(StaticRootInvalid, "静态目录为空")
	}
	if strings.ContainsAny(p, "\r\n\x00") {
		return "", staticRootErr(StaticRootInvalid, "静态目录包含非法字符(换行或空字符)")
	}
	cleaned := filepath.Clean(p)
	if !filepath.IsAbs(cleaned) {
		return "", staticRootErr(StaticRootInvalid, "静态目录必须是绝对路径: %s", raw)
	}
	if runtime.GOOS == "windows" && hasWindowsDevicePrefix(cleaned) {
		return "", staticRootErr(StaticRootInvalid, "静态目录不支持 Windows 设备路径前缀(\\\\?\\ 或 \\\\.\\): %s", raw)
	}
	cleaned = staticComparePath(cleaned)
	if err := checkStaticRootPolicy(cleaned, staticSiteAllowedRoots(), staticSiteProtectedRoots(), []string{StaticSiteDefaultDir()}); err != nil {
		return "", err
	}
	realPath, ok := resolveStaticRealPath(cleaned)
	if !ok {
		return "", staticRootErr(StaticRootInvalid, "静态目录无法解析(链接链过长): %s", cleaned)
	}
	realPath = filepath.Clean(realPath)
	if err := checkStaticRootPolicy(realPath, realAllowedRoots(), realRoots(staticSiteProtectedRoots()), []string{realStaticSiteDefaultDir()}); err != nil {
		if !samePath(realPath, cleaned) {
			return "", staticRootErr(StaticRootErrorCode(err), "静态目录经链接指向 %s，%s", realPath, err.Error())
		}
		return "", err
	}
	return staticComparePath(cleaned), nil
}

func checkStaticRootPolicy(p string, allowed, protected, defaults []string) error {
	if isProtectedStaticPath(p, protected, defaults, staticSiteProtectedFiles()) {
		return staticRootErr(StaticRootProtected, "静态目录不能使用 SamWaf 的配置或数据目录（内置静态目录 %s 除外）: %s", StaticSiteDefaultDir(), p)
	}
	if !staticAtOrUnderAny(allowed, p) {
		return staticRootErr(StaticRootNotAllowed, "静态目录不在允许目录内（请使用内置目录 %s，或在 config.yml 的 security.static_site_allowed_dirs 声明该目录）: %s", StaticSiteDefaultDir(), p)
	}
	return nil
}

// staticProtectedSet 运行时判定用的真实路径集合，按程序目录与密钥文件配置缓存。
type staticProtectedSet struct {
	key        string
	protected  []string
	defaults   []string
	files      []string
	failClosed bool // 受保护目录自身无法解析时整站拒绝伺服
}

var staticProtectedCache atomic.Pointer[staticProtectedSet]

func currentStaticProtectedSet() *staticProtectedSet {
	key := staticSiteAbsBase() + "|" + global.GCONFIG_DATA_KEY_FILE + "|" + global.GCONFIG_COMM_KEY_FILE
	if ps := staticProtectedCache.Load(); ps != nil && ps.key == key {
		return ps
	}
	protected, ok := realRootsChecked(staticSiteProtectedRoots())
	ps := &staticProtectedSet{
		key:        key,
		protected:  protected,
		defaults:   []string{realStaticSiteDefaultDir()},
		files:      realFiles(staticSiteProtectedFiles()),
		failClosed: !ok,
	}
	staticProtectedCache.Store(ps)
	return ps
}

// IsProtectedStaticFile 运行时判定：将要伺服的文件按真实路径是否落在程序自身的配置/数据目录
// （内置默认静态目录除外）或是自定义密钥文件。p 须为绝对路径；路径无法解析时按受保护处理。
func IsProtectedStaticFile(p string) bool {
	realPath, ok := resolveStaticRealPath(p)
	if !ok {
		return true
	}
	ps := currentStaticProtectedSet()
	if ps.failClosed {
		return true
	}
	return isProtectedStaticPath(filepath.Clean(realPath), ps.protected, ps.defaults, ps.files)
}

// realStaticSiteDefaultDir 内置默认静态目录的真实路径：由 data 的真实路径加目录名推出，
// 不解析最后一级本身——最后一级被换成指向别处的链接时，它不应因此成为允许根或豁免受保护目录。
func realStaticSiteDefaultDir() string {
	def := StaticSiteDefaultDir()
	base := staticSiteAbsBase()
	if base == "" {
		return def
	}
	if rd, ok := resolveStaticRealPath(filepath.Join(base, "data")); ok {
		return filepath.Clean(filepath.Join(rd, filepath.Base(def)))
	}
	return def
}

// realAllowedRoots 允许根的真实路径。内置默认目录按 data 的真实路径推导，其余按链接目标解析。
func realAllowedRoots() []string {
	roots := staticSiteAllowedRoots()
	def := StaticSiteDefaultDir()
	out := make([]string, 0, len(roots))
	for _, root := range roots {
		if samePath(root, def) {
			out = append(out, realStaticSiteDefaultDir())
			continue
		}
		if real, ok := resolveStaticRealPath(root); ok {
			out = append(out, filepath.Clean(real))
		} else {
			out = append(out, root)
		}
	}
	return out
}

func realFiles(files []string) []string {
	out := make([]string, 0, len(files)*2)
	for _, f := range files {
		out = append(out, filepath.Clean(f))
		if real, ok := resolveStaticRealPath(f); ok {
			out = append(out, filepath.Clean(real))
		}
	}
	return out
}

// SameStaticRoot 判断两个静态目录配置是否指向同一路径（去空白、Clean 后按平台路径规则比较）。
func SameStaticRoot(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == "" || b == "" {
		return a == b
	}
	return staticSamePath(a, b)
}
