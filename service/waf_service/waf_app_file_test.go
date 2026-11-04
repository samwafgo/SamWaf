package waf_service

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"
)

func appTestMode(mode os.FileMode) *os.FileMode {
	return &mode
}

func checkAppFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != content {
		t.Fatalf("content=%q err=%v, want %q", raw, err, content)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != mode.Perm() {
		t.Fatalf("mode=%#o, want %#o", info.Mode().Perm(), mode.Perm())
	}
}

func checkAppFileTempCleaned(t *testing.T, dir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, ".samwaf-upload-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary files=%v err=%v", matches, err)
	}
}

func TestAppFileNewFileExecutableRespectsUmask(t *testing.T) {
	dir := t.TempDir()
	control := filepath.Join(dir, "control")
	if err := os.WriteFile(control, []byte("control"), 0666); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(control)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "new")
	if err := writeAppFile(path, strings.NewReader("new"), nil, ""); err != nil {
		t.Fatal(err)
	}
	wantMode := info.Mode().Perm()
	if runtime.GOOS != "windows" {
		wantMode |= 0100
	}
	checkAppFile(t, path, "new", wantMode)
	checkAppFileTempCleaned(t, dir)
}

func TestAppFileReplacementMode(t *testing.T) {
	for _, mode := range []os.FileMode{0755, 0750, 0700, 0644, 0640, 0600, 0444} {
		t.Run(mode.String(), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "server")
			if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
				t.Fatal(err)
			}
			if err := writeAppFile(path, strings.NewReader("new"), &mode, ""); err != nil {
				t.Fatal(err)
			}
			checkAppFile(t, path, "new", mode)
			checkAppFileTempCleaned(t, dir)
			if runtime.GOOS == "windows" {
				t.Cleanup(func() { _ = os.Chmod(path, 0666) })
			}
		})
	}
}

func TestAppFileFailureKeepsOriginal(t *testing.T) {
	for _, scenario := range []string{"hash", "read"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "server")
			if err := os.WriteFile(path, []byte("original"), 0750); err != nil {
				t.Fatal(err)
			}
			var src io.Reader = strings.NewReader("replacement")
			expected := strings.Repeat("0", 64)
			if scenario == "read" {
				src = io.MultiReader(strings.NewReader("partial"), iotest.ErrReader(errors.New("read failed")))
				expected = ""
			}
			if err := os.Chmod(path, 0750); err != nil {
				t.Fatal(err)
			}
			if err := writeAppFile(path, src, appTestMode(0644), expected); err == nil {
				t.Fatal("expected failure")
			}
			checkAppFile(t, path, "original", 0750)
			checkAppFileTempCleaned(t, dir)
		})
	}
}

func TestAppFileHashCaseAndRenameFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server")
	hash := sha256.Sum256([]byte("new"))
	if err := writeAppFile(path, strings.NewReader("new"), appTestMode(0644), strings.ToUpper(hex.EncodeToString(hash[:]))); err != nil {
		t.Fatal(err)
	}
	checkAppFile(t, path, "new", 0644)
	if err := writeAppFile(dir, strings.NewReader("new"), appTestMode(0644), ""); err == nil {
		t.Fatal("replacing a directory must fail")
	}
	checkAppFile(t, path, "new", 0644)
	checkAppFileTempCleaned(t, filepath.Dir(dir))
}

func TestAppFileCopyPreservesSourceMode(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "server"), filepath.Join(dir, "backup")
	if err := os.WriteFile(src, []byte("old version"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(src, 0750); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, dst); err != nil {
		t.Fatal(err)
	}
	checkAppFile(t, dst, "old version", 0750)
	if err := os.Chmod(dst, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(src, 0750); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, dst); err != nil {
		t.Fatal(err)
	}
	checkAppFile(t, dst, "old version", 0750)
}

func TestAppFileExecutableAfterFirstUploadAndCopy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires Unix execute permissions and /bin/sh")
	}
	dir := t.TempDir()
	path, backup := filepath.Join(dir, "server"), filepath.Join(dir, "backup")
	if err := writeAppFile(path, strings.NewReader("#!/bin/sh\nprintf 'app-permission-ok\\n'\n"), nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(path, backup); err != nil {
		t.Fatal(err)
	}
	for _, executable := range []string{path, backup} {
		out, err := exec.Command(executable).CombinedOutput()
		if err != nil || string(out) != "app-permission-ok\n" {
			t.Fatalf("execute %s: %q err=%v", executable, out, err)
		}
	}
}
