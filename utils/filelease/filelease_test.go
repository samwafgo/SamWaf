package filelease

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func lockHelperPath(t *testing.T) string {
	t.Helper()
	if os.Getenv("SAMWAF_FILELEASE_HELPER") == "1" {
		return ""
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

func startLockHolder(t *testing.T, mode, path string) (*exec.Cmd, <-chan error) {
	t.Helper()
	cmd := exec.Command(lockHelperPath(t), "-test.run=TestFileLeaseHelperProcess", "-test.v")
	cmd.Env = append(os.Environ(),
		"SAMWAF_FILELEASE_HELPER=1",
		"SAMWAF_FILELEASE_MODE="+mode,
		"SAMWAF_FILELEASE_PATH="+path,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})
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
	return cmd, ready
}

func waitLockHolder(t *testing.T, ready <-chan error) {
	t.Helper()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatalf("lock holder not ready: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for lock holder")
	}
}

var helperHeld *Lease

// TestFileLeaseHelperProcess is never run directly; it is the child process used above.
func TestFileLeaseHelperProcess(t *testing.T) {
	if os.Getenv("SAMWAF_FILELEASE_HELPER") != "1" {
		return
	}
	mode := os.Getenv("SAMWAF_FILELEASE_MODE")
	path := os.Getenv("SAMWAF_FILELEASE_PATH")
	ctx := context.Background()
	var err error
	switch mode {
	case "shared":
		helperHeld, err = AcquireShared(ctx, path)
	case "exclusive":
		helperHeld, err = AcquireExclusive(ctx, path)
	default:
		err = fmt.Errorf("unknown mode %q", mode)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "helper acquire: %v", err)
		os.Exit(2)
	}
	fmt.Println("locked")
	// Keep the descriptor open until the parent kills this process.
	for {
		time.Sleep(time.Hour)
	}
}

func TestFileLeaseCrossProcessSharedAndExclusive(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns helper process")
	}
	path := filepath.Join(t.TempDir(), "lease.lock")

	shared, sharedReady := startLockHolder(t, "shared", path)
	waitLockHolder(t, sharedReady)
	ctx := context.Background()
	got, err := AcquireShared(ctx, path)
	if err != nil {
		t.Fatalf("shared locks should coexist across processes: %v", err)
	}
	got.Release()
	got.Release()

	ctxTimeout, cancel := context.WithTimeout(ctx, 80*time.Millisecond)
	defer cancel()
	if lease, err := AcquireExclusive(ctxTimeout, path); !errors.Is(err, context.DeadlineExceeded) {
		if lease != nil {
			lease.Release()
		}
		t.Fatalf("exclusive lock must wait for foreign shared lock: %v", err)
	}
	_ = shared.Process.Kill()
	_ = shared.Wait()

	exclusive, exclusiveReady := startLockHolder(t, "exclusive", path)
	waitLockHolder(t, exclusiveReady)
	ctxTimeout, cancel = context.WithTimeout(ctx, 80*time.Millisecond)
	defer cancel()
	if lease, err := AcquireShared(ctxTimeout, path); !errors.Is(err, context.DeadlineExceeded) {
		if lease != nil {
			lease.Release()
		}
		t.Fatalf("shared lock must wait for foreign exclusive lock: %v", err)
	}
	_ = exclusive.Process.Kill()
	_ = exclusive.Wait()

	got, err = AcquireShared(ctx, path)
	if err != nil {
		t.Fatalf("lock not released by terminated process: %v", err)
	}
	got.Release()
}

func TestFileLeaseRejectsSymlinkAndReleaseIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.lock")
	link := filepath.Join(dir, "link.lock")
	lease, err := AcquireShared(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
	lease.Release()
	if err := lease.Err(); err != nil {
		t.Fatalf("release returned error: %v", err)
	}
	if runtime.GOOS == "windows" {
		t.Skip("symlink privilege is not guaranteed on Windows")
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if lease, err := AcquireShared(context.Background(), link); err == nil {
		lease.Release()
		t.Fatal("symlink lock path accepted")
	} else if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("unexpected symlink rejection error: %v", err)
	}
}
