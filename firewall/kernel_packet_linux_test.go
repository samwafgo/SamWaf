//go:build linux

package firewall

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// testKernelFragments 验证真实重组路径：TCP 端口封禁不应误伤同来源的分片 UDP，整 IP 封禁必须生效。
func testKernelFragments(t *testing.T, fw *FireWallEngine) {
	if os.Geteuid() != 0 {
		t.Skip("raw packet generator requires CAP_NET_RAW; covered by the separate root suite")
	}
	for _, family := range []int{4, 6} {
		t.Run(map[int]string{4: "fragment-v4", 6: "fragment-v6-extensions"}[family], func(t *testing.T) {
			network, listen, source := "udp4", "127.0.0.1:0", "127.0.0.2"
			if family == 6 {
				network, listen, source = "udp6", "[::1]:0", "fd00:57::2"
			}
			listener, err := net.ListenPacket(network, listen)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			destination := listener.LocalAddr().(*net.UDPAddr)
			group := "fragment-test"
			send := func(want bool) {
				t.Helper()
				_ = listener.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
				packets, payload := fragmentUDP(family, net.ParseIP(source), destination.IP, destination.Port, uint32(time.Now().UnixNano()))
				if family == 6 && os.Getenv("SAMWAF_EBPF_PACKET_DEBUG") == "1" {
					t.Logf("generated IPv6 fragments: %x %x", packets[0], packets[1])
				}
				if err := sendRawIP(family, destination.IP, packets); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 128)
				n, _, err := listener.ReadFrom(buf)
				if (err == nil) != want {
					if family == 6 {
						stats, _ := os.ReadFile("/proc/net/snmp6")
						t.Logf("isolated IPv6 counters:\n%s", stats)
					}
					t.Fatalf("IPv%d fragment delivery=%v want %v: %v", family, err == nil, want, err)
				}
				if want && !bytes.Equal(buf[:n], payload) {
					t.Fatal("reassembly changed UDP payload")
				}
			}
			send(true)
			if err = fw.ApplyIPSetPortScope(group, []int{destination.Port}); err != nil {
				t.Fatal(err)
			}
			if err = fw.RestoreIPSet(group, []string{source}); err != nil {
				t.Fatal(err)
			}
			send(true) // 若没有正确重组，端口解析失败标记会错误拒绝这份合法 UDP。
			if err = fw.BlockIP(source, "fragment test"); err != nil {
				t.Fatal(err)
			}
			send(false)
			if err = fw.UnblockIP(source); err != nil {
				t.Fatal(err)
			}
			send(true)
			if err = fw.DestroyIPSet(group); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// packetChecksum 对测试报文和 IPv6 伪头计算 RFC 规定的一补和校验。
func packetChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) > 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}

// fragmentUDP 构造两个分片，IPv6 同时包含目的选项扩展头，避免只测试固定 40 字节头部。
func fragmentUDP(family int, source, destination net.IP, port int, id uint32) ([][]byte, []byte) {
	payload := []byte("samwaf-fragment-payload")
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp, 31000)
	binary.BigEndian.PutUint16(udp[2:], uint16(port))
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], payload)
	if family == 6 {
		pseudo := make([]byte, 40+len(udp))
		copy(pseudo, source.To16())
		copy(pseudo[16:], destination.To16())
		binary.BigEndian.PutUint32(pseudo[32:], uint32(len(udp)))
		pseudo[39] = 17
		copy(pseudo[40:], udp)
		checksum := packetChecksum(pseudo)
		if checksum == 0 {
			checksum = 65535
		}
		binary.BigEndian.PutUint16(udp[6:], checksum)
	}
	fragmentable := udp
	if family == 6 {
		fragmentable = make([]byte, 8+len(udp))
		fragmentable[0] = 17
		copy(fragmentable[8:], udp)
	}
	packets := [][]byte{}
	for index, part := range [][]byte{fragmentable[:16], fragmentable[16:]} {
		if family == 4 {
			packet := make([]byte, 20+len(part))
			packet[0] = 0x45
			binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
			binary.BigEndian.PutUint16(packet[4:], uint16(id))
			fragment := uint16(0x2000)
			if index == 1 {
				fragment = 2
			}
			binary.BigEndian.PutUint16(packet[6:], fragment)
			packet[8] = 64
			packet[9] = 17
			copy(packet[12:], source.To4())
			copy(packet[16:], destination.To4())
			binary.BigEndian.PutUint16(packet[10:], packetChecksum(packet[:20]))
			copy(packet[20:], part)
			packets = append(packets, packet)
		} else {
			packet := make([]byte, 48+len(part))
			packet[0] = 0x60
			binary.BigEndian.PutUint16(packet[4:], uint16(len(packet)-40))
			packet[6] = 44
			packet[7] = 64
			copy(packet[8:], source.To16())
			copy(packet[24:], destination.To16())
			packet[40] = 60 // 目的选项属于可分片部分，放在 Fragment 之后。
			fragment := uint16(1)
			if index == 1 {
				fragment = 16
			}
			binary.BigEndian.PutUint16(packet[42:], fragment)
			binary.BigEndian.PutUint32(packet[44:], id)
			copy(packet[48:], part)
			packets = append(packets, packet)
		}
	}
	return packets, payload
}

// sendRawIP 从 AF_PACKET 注入 loopback 二层入口，绕过 LOCAL_OUT，真实覆盖 PREROUTING/LOCAL_IN。
// 仅测试流量生成器需要 CAP_NET_RAW，运行时封禁进程不需要该能力。
func sendRawIP(family int, _ net.IP, packets [][]byte) error {
	etherType := uint16(unix.ETH_P_IP)
	if family == 6 {
		etherType = unix.ETH_P_IPV6
	}
	protocol := int((etherType<<8)&0xff00 | etherType>>8)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, protocol)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		return err
	}
	target := &unix.SockaddrLinklayer{Ifindex: iface.Index, Protocol: uint16(protocol), Halen: 6}
	for _, packet := range packets {
		frame := make([]byte, 14+len(packet))
		binary.BigEndian.PutUint16(frame[12:], etherType)
		copy(frame[14:], packet)
		if err = unix.Sendto(fd, frame, 0, target); err != nil {
			return err
		}
	}
	return nil
}
