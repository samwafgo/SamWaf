package waf_service

import (
	"SamWaf/model/request"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAppUploadPreservesExistingMode(t *testing.T) {
	setupAppDirEnv(t)
	app, err := WafAppServiceApp.AddApi(request.WafAppAddReq{Code: "app-upload-mode", Name: "upload mode", StartCmd: "./server"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		mode os.FileMode
	}{
		{"server", 0750}, {"config.env", 0600}, {"new.txt", 0644},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(app.AppDir, tc.name)
			if tc.name != "new.txt" {
				if err := os.WriteFile(path, []byte("old"), tc.mode); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, tc.mode); err != nil {
					t.Fatal(err)
				}
			} else {
				control := filepath.Join(app.AppDir, "control")
				if err := os.WriteFile(control, nil, 0666); err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(control)
				if err != nil {
					t.Fatal(err)
				}
				tc.mode = info.Mode().Perm()
				if runtime.GOOS != "windows" {
					tc.mode |= 0100
				}
			}
			if err := WafAppServiceApp.UploadFile(app.Code, tc.name, strings.NewReader("new"), ""); err != nil {
				t.Fatal(err)
			}
			checkAppFile(t, path, "new", tc.mode)
		})
	}
	path := filepath.Join(app.AppDir, "server")
	if err := WafAppServiceApp.UploadFile(app.Code, "server", strings.NewReader("bad"), strings.Repeat("0", 64)); err == nil {
		t.Fatal("invalid hash must fail")
	}
	checkAppFile(t, path, "new", 0750)
	checkAppFileTempCleaned(t, app.AppDir)
}

func TestAppUpgradeRollbackPreservesFileMode(t *testing.T) {
	setupAppDirEnv(t)
	app, err := WafAppServiceApp.AddApi(request.WafAppAddReq{Code: "app-upgrade-mode", Name: "upgrade mode", StartCmd: "./server"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(app.AppDir, "server")
	if err := os.WriteFile(path, []byte("version one"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0750); err != nil {
		t.Fatal(err)
	}
	if err := WafAppServiceApp.UpgradeApp(app.Code, "server", strings.NewReader("version two"), ""); err != nil {
		t.Fatal(err)
	}
	checkAppFile(t, path, "version two", 0750)
	backups, err := WafAppServiceApp.ListBackups(app.Code)
	if err != nil || len(backups) != 1 {
		t.Fatalf("backups=%v err=%v", backups, err)
	}
	checkAppFile(t, filepath.Join(app.AppDir, "backup", backups[0].Filename), "version one", 0750)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := WafAppServiceApp.RollbackApp(app.Code, backups[0].Filename); err != nil {
		t.Fatal(err)
	}
	checkAppFile(t, path, "version one", 0750)
	checkAppFileTempCleaned(t, app.AppDir)
}
