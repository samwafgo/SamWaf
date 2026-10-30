package wafdb

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var lifecycleHelperHeld func()

// TestLogLifecycleHelperProcess is spawned by TestLogLifecycleCrossProcessFileLease.
func TestLogLifecycleHelperProcess(t *testing.T) {
	if os.Getenv("SAMWAF_WAFDB_LEASE_HELPER") != "1" {
		return
	}
	SetLogLifecycleLockPath(os.Getenv("SAMWAF_WAFDB_LOCK_PATH"))
	ctx := context.Background()
	var release func()
	var err error
	switch os.Getenv("SAMWAF_WAFDB_LOCK_MODE") {
	case "read":
		release, err = AcquireLogRead(ctx)
	case "write":
		release, err = AcquireLogWrite(ctx)
	default:
		err = fmt.Errorf("unknown mode")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	lifecycleHelperHeld = release
	fmt.Println("locked")
	for {
		time.Sleep(time.Hour)
	}
}

func TestLogLifecycleCrossProcessFileLease(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns helper process")
	}
	oldPath := logLifecycleLockPath
	lockPath := filepath.Join(t.TempDir(), "lifecycle.lock")
	SetLogLifecycleLockPath(lockPath)
	t.Cleanup(func() { SetLogLifecycleLockPath(oldPath) })

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=TestLogLifecycleHelperProcess", "-test.v")
	cmd.Env = append(os.Environ(),
		"SAMWAF_WAFDB_LEASE_HELPER=1",
		"SAMWAF_WAFDB_LOCK_MODE=read",
		"SAMWAF_WAFDB_LOCK_PATH="+lockPath,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ready := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(stdout)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				ready <- err
				return
			}
			if strings.TrimSpace(line) == "locked" {
				ready <- nil
				return
			}
		}
	}()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatalf("helper not ready: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for helper")
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})

	ctx := context.Background()
	r, err := AcquireLogRead(ctx)
	if err != nil {
		t.Fatalf("read leases should share across processes: %v", err)
	}
	r()
	r()

	wctx, cancel := context.WithTimeout(ctx, 80*time.Millisecond)
	defer cancel()
	if release, err := AcquireLogWrite(wctx); !errors.Is(err, context.DeadlineExceeded) {
		if release != nil {
			release()
		}
		t.Fatalf("write lease must wait for foreign reader: %v", err)
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	w, err := AcquireLogWrite(ctx)
	if err != nil {
		t.Fatalf("write lease not released by terminated helper: %v", err)
	}
	w()
}
