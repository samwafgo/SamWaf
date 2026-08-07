//go:build linux

package wafhostguard

import (
	"SamWaf/common/zlog"
	"bufio"
	"context"
	"io"
	"os"
	"syscall"
	"time"
)

// 认证日志的 tail 实现。三个必须处理好的细节：
//
//  1. **首次打开必须 Seek 到末尾**。日志里常年积着几万条历史 Failed password，
//     从头读会把它们全当成"刚刚发生"，SamWaf 一启动就把一大批早就无害的 IP 全封了。
//  2. **logrotate 的两种模式都要认**：create 模式下旧文件被 rename、新文件 inode 变了；
//     copytruncate 模式下 inode 不变但文件被截断(size 变得比当前偏移小)。
//  3. **文件可能暂时不存在**：轮转的瞬间、或者 rsyslog 还没来得及创建，
//     这时不能直接报错退出，要重试等它出现。

// fileTail 单个日志文件的跟随读取器
type fileTail struct {
	path   string
	f      *os.File
	rd     *bufio.Reader
	ino    uint64
	offset int64
}

// fileTailSource 实现 Source 接口
type fileTailSource struct {
	path string
}

func (s *fileTailSource) Name() string { return "file:" + s.path }

func (s *fileTailSource) Run(ctx context.Context, out chan<- LoginFailEvent) error {
	t := &fileTail{path: s.path}
	defer t.close()

	// 第一次打开从末尾开始，只关心"从现在起"发生的事
	if err := t.open(true); err != nil {
		zlog.Warn("[主机登录防护] 打开认证日志失败，将持续重试", "path", s.path, "error", err.Error())
	}

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		if t.f == nil {
			// 文件还没出现(或上次打开失败)，重试；轮转后的新文件要从头读，
			// 否则轮转瞬间写入的那几行会被跳过
			if err := t.open(false); err != nil {
				continue
			}
			zlog.Info("[主机登录防护] 认证日志已就绪", "path", s.path)
		}

		if err := t.readLines(ctx, out); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			zlog.Debug("[主机登录防护] 读取认证日志出错，将重新打开", "path", s.path, "error", err.Error())
			t.close()
			continue
		}
		if err := t.checkRotate(); err != nil {
			zlog.Debug("[主机登录防护] 检查日志轮转出错", "path", s.path, "error", err.Error())
		}
	}
}

// open 打开文件。fromEnd=true 时定位到末尾(仅首次)，否则从头读(轮转后的新文件)
func (t *fileTail) open(fromEnd bool) error {
	f, err := os.Open(t.path)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	t.f = f
	t.ino = inodeOf(st)
	if fromEnd {
		off, err := f.Seek(0, io.SeekEnd)
		if err != nil {
			_ = f.Close()
			t.f = nil
			return err
		}
		t.offset = off
	} else {
		t.offset = 0
	}
	t.rd = bufio.NewReader(f)
	return nil
}

func (t *fileTail) close() {
	if t.f != nil {
		_ = t.f.Close()
		t.f = nil
	}
	t.rd = nil
}

// readLines 读到 EOF 为止，把解析出的事件发给 out
func (t *fileTail) readLines(ctx context.Context, out chan<- LoginFailEvent) error {
	for {
		line, err := t.rd.ReadString('\n')
		if len(line) > 0 {
			t.offset += int64(len(line))
			if ev, ok := ParseSSHDLine(trimNewline(line), time.Now()); ok {
				select {
				case out <- ev:
				case <-ctx.Done():
					return nil
				default:
					// 通道满说明消费端跟不上(极端爆破场景)。丢事件也不能阻塞采集，
					// 否则 fd 里的数据积压会越来越多，最终连"现在发生了什么"都读不到。
					dropEvent()
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// checkRotate 检测轮转与截断
func (t *fileTail) checkRotate() error {
	st, err := os.Stat(t.path)
	if err != nil {
		// 文件消失了(轮转中间态)，关掉等下一轮重开
		t.close()
		return nil
	}
	// create 模式：路径指向了新 inode
	if inodeOf(st) != t.ino {
		zlog.Info("[主机登录防护] 检测到日志轮转(文件已更换)，重新打开", "path", t.path)
		t.close()
		return nil
	}
	// copytruncate 模式：inode 没变但文件被清空了
	if st.Size() < t.offset {
		zlog.Info("[主机登录防护] 检测到日志被截断，从头继续读取", "path", t.path)
		if _, err := t.f.Seek(0, io.SeekStart); err != nil {
			t.close()
			return err
		}
		t.offset = 0
		t.rd = bufio.NewReader(t.f)
	}
	return nil
}

// inodeOf 取文件 inode，拿不到时返回 0(0 不会与真实 inode 冲突，最坏是多重开一次)
func inodeOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}

func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
