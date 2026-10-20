package wafconfig

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/spf13/viper"
)

func preserveAdminTitles(t *testing.T) {
	t.Helper()
	prior := GetAdminTitles()
	t.Cleanup(func() {
		adminTitlesState.Lock()
		adminTitlesState.titles = prior
		adminTitlesState.Unlock()
	})
}

func TestAdminTitlesPersistAndLoad(t *testing.T) {
	preserveAdminTitles(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(path, []byte("local_port: 26666\nnotice:\n  title: existing\n"), 0600); err != nil {
		t.Fatal(err)
	}
	want := AdminTitles{AdminTitle: "管理后台 & Ops"}
	if err := updateAdminTitles(dir, want); err != nil {
		t.Fatal(err)
	}
	if got := GetAdminTitles(); got != want {
		t.Fatalf("runtime titles = %#v, want %#v", got, want)
	}
	config := viper.New()
	config.SetConfigFile(path)
	if err := config.ReadInConfig(); err != nil {
		t.Fatal(err)
	}
	if config.GetString("notice.title") != "existing" || config.GetInt("local_port") != 26666 {
		t.Fatal("existing config was not preserved")
	}
	ui := config.GetStringMapString("ui")
	if len(ui) != 1 || ui["admin_title"] != want.AdminTitle {
		t.Fatalf("unexpected ui config: %#v", ui)
	}
	loadAdminTitles(viper.New())
	if GetAdminTitles() != (AdminTitles{}) {
		t.Fatal("missing config must load empty defaults")
	}
	loadAdminTitles(config)
	if got := GetAdminTitles(); got != want {
		t.Fatalf("loaded titles = %#v, want %#v", got, want)
	}
	if err := updateAdminTitles(dir, AdminTitles{}); err != nil {
		t.Fatal(err)
	}
	if err := config.ReadInConfig(); err != nil {
		t.Fatal(err)
	}
	if !config.IsSet("ui.admin_title") || config.GetString("ui.admin_title") != "" {
		t.Fatal("empty admin title must persist under ui.admin_title")
	}
	loadAdminTitles(config)
	if GetAdminTitles() != (AdminTitles{}) {
		t.Fatal("empty titles must persist")
	}
}

func TestAdminTitlesPersistenceFailureKeepsSnapshot(t *testing.T) {
	preserveAdminTitles(t)
	dir := t.TempDir()
	prior := AdminTitles{AdminTitle: "prior"}
	if err := updateAdminTitles(dir, prior); err != nil {
		t.Fatal(err)
	}
	config := viper.New()
	config.SetConfigFile(dir)
	config.SetConfigType("yml")
	adminTitlesState.Lock()
	err := persistAdminTitles(config, AdminTitles{AdminTitle: "next"}, false)
	adminTitlesState.Unlock()
	if err == nil {
		t.Fatal("expected config write failure")
	}
	if GetAdminTitles() != prior {
		t.Fatal("write failure changed runtime titles")
	}
	path := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(path, []byte("ui: [invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := updateAdminTitles(dir, AdminTitles{AdminTitle: "next"}); err == nil {
		t.Fatal("expected config read failure")
	}
	if GetAdminTitles() != prior {
		t.Fatal("failed persistence changed runtime titles")
	}
	if err := updateAdminTitles(path, AdminTitles{}); err == nil {
		t.Fatal("expected config directory failure")
	}
	if GetAdminTitles() != prior {
		t.Fatal("directory failure changed runtime titles")
	}
}

func TestAdminTitlesCreateAndConcurrentSnapshot(t *testing.T) {
	preserveAdminTitles(t)
	dir := t.TempDir()
	if err := updateAdminTitles(dir, AdminTitles{}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			got := GetAdminTitles()
			switch got.AdminTitle {
			case "", "one", "two":
			default:
				t.Errorf("unexpected snapshot: %#v", got)
				return
			}
		}
	}()
	for _, title := range []string{"one", "two", ""} {
		if err := updateAdminTitles(dir, AdminTitles{AdminTitle: title}); err != nil {
			t.Error(err)
		}
	}
	wg.Wait()
}
