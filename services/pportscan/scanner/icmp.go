//go:build linux || darwin

package scanner

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"

	iputil "github.com/projectdiscovery/utils/ip"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	originTimestamp   = 4
	receiveTimestamp  = 8
	transmitTimestamp = 12
)

func init() {
	pingIcmpEchoRequestCallback = PingIcmpEchoRequest
	pingIcmpEchoRequestAsyncCallback = PingIcmpEchoRequestAsync
	pingIcmpTimestampRequestCallback = PingIcmpTimestampRequest
	pingIcmpTimestampRequestAsyncCallback = PingIcmpTimestampRequestAsync
	pingIcmpAddressMaskRequestAsyncCallback = PingIcmpAddressMaskRequestAsync
	pingNdpRequestAsyncCallback = PingNdpRequestAsync
}

// PingIcmpEchoRequest 与目标 IP 地址同步
func PingIcmpEchoRequest(ip string, timeout time.Duration) bool {
	destAddr := &net.IPAddr{IP: net.ParseIP(ip)}
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false
	}
	defer c.Close()

	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Data: []byte(""),
		},
	}

	data, err := m.Marshal(nil)
	if err != nil {
		return false
	}

	_, err = c.WriteTo(data, destAddr)
	if err != nil {
		return false
	}

	reply := make([]byte, 1500)
	err = c.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return false
	}
	n, SourceIP, err := c.ReadFrom(reply)
	// timeout
	if err != nil {
		return false
	}
	// 如果从连接中读取任何内容，则表示主机处于活动状态
	if destAddr.String() == SourceIP.String() && n > 0 {
		return true
	}

	return false
}

// PingIcmpEchoRequestAsync 异步发送 ICMP 回显请求（ping 请求）到指定的 IP 地址
func PingIcmpEchoRequestAsync(s *Scanner, ip string) {
	destinationIP := net.ParseIP(ip)
	var destAddr net.Addr
	// ICMP 消息
	m := icmp.Message{
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff, // 当前进程 ID 与 0xffff 进行位于操作生成 ICMP 消息的标识符
			Seq:  1,                    // 序列号
			Data: []byte(""),
		},
	}

	var packetListener net.PacketConn
	switch {
	case iputil.IsIPv4(ip):
		m.Type = ipv4.ICMPTypeEcho
		packetListener = s.icmpPacketListener4
		destAddr = &net.IPAddr{IP: destinationIP}
	case iputil.IsIPv6(ip):
		m.Type = ipv6.ICMPTypeEchoRequest
		packetListener = s.icmpPacketListener6
		networkInterface, _, _, err := s.Router.Route(destinationIP)
		if networkInterface == nil {
			err = fmt.Errorf("could not send ICMP Echo Request packet to %s: no interface with outbout source ipv6 found", destinationIP)
		}
		if err != nil {
			return
		}
		destAddr = &net.UDPAddr{IP: destinationIP, Zone: networkInterface.Name}
	}

	data, err := m.Marshal(nil)
	if err != nil {
		return
	}
	retries := 0
send:
	if retries >= maxRetries {
		return
	}
	_, err = packetListener.WriteTo(data, destAddr)
	if err != nil {
		retries++
		// 引入小延迟以允许网络接口刷新队列
		time.Sleep(time.Duration(DeadlineSec) * time.Millisecond)
		goto send
	}
}

// PingIcmpTimestampRequest 与目标 IP 地址同步
func PingIcmpTimestampRequest(ip string, timeout time.Duration) bool {
	destAddr := &net.IPAddr{IP: net.ParseIP(ip)}
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false
	}
	defer c.Close()

	m := icmp.Message{
		Type: ipv4.ICMPTypeTimestamp,
		Code: 0,
		Body: &Timestamp{
			ID:              os.Getpid() & 0xffff,
			Seq:             0,
			OriginTimestamp: 0,
		},
	}

	data, err := m.Marshal(nil)
	if err != nil {
		return false
	}

	_, err = c.WriteTo(data, destAddr)
	if err != nil {
		return false
	}

	reply := make([]byte, 1500)
	err = c.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return false
	}

	n, SourceIP, err := c.ReadFrom(reply)
	// timeout
	if err != nil {
		return false
	}
	// 如果从连接中读取任何内容，则表示主机处于活动状态
	if destAddr.String() == SourceIP.String() && n > 0 {
		return true
	}

	return false
}

// PingIcmpTimestampRequestAsync 向指定的 IPv4 地址发送 ICMP 时间戳请求
func PingIcmpTimestampRequestAsync(s *Scanner, ip string) {
	if !iputil.IsIPv4(ip) {
		return
	}
	destAddr := &net.IPAddr{IP: net.ParseIP(ip)}
	m := icmp.Message{
		Type: ipv4.ICMPTypeTimestamp,
		Code: 0,
		Body: &Timestamp{
			ID:              os.Getpid() & 0xffff, // 当前进程 ID 与 0xffff 进行位于操作生成 ICMP 消息的标识符
			Seq:             0,                    // 序列号
			OriginTimestamp: 0,
		},
	}

	data, err := m.Marshal(nil)
	if err != nil {
		return
	}

	_, err = s.icmpPacketListener4.WriteTo(data, destAddr)
	if err != nil {
		return
	}
}

// Timestamp ICMP structure
type Timestamp struct {
	ID                int
	Seq               int
	OriginTimestamp   uint32
	ReceiveTimestamp  uint32
	TransmitTimestamp uint32
}

const marshalledTimestampLen = 16

// Len 返回默认时间戳长度
func (t *Timestamp) Len(_ int) int {
	if t == nil {
		return 0
	}
	return marshalledTimestampLen
}

// Marshal 时间戳结构
func (t *Timestamp) Marshal(_ int) ([]byte, error) {
	bSize := marshalledTimestampLen / 2
	b := make([]byte, marshalledTimestampLen)
	b[0], b[1] = byte(t.ID>>bSize), byte(t.ID)
	b[2], b[3] = byte(t.Seq>>bSize), byte(t.Seq)

	unparseInt := func(i uint32) (byte, byte, byte, byte) {
		bs := make([]byte, 4)
		binary.LittleEndian.PutUint32(bs, i)
		return bs[3], bs[2], bs[1], bs[0]
	}

	b[4], b[5], b[6], b[7] = unparseInt(t.OriginTimestamp)
	b[8], b[9], b[10], b[11] = unparseInt(t.ReceiveTimestamp)
	b[12], b[13], b[14], b[15] = unparseInt(t.TransmitTimestamp)
	return b, nil
}

// ParseTimestamp to MessageBody structure
func ParseTimestamp(_ int, b []byte) (icmp.MessageBody, error) {
	bodyLen := len(b)
	if bodyLen != marshalledTimestampLen {
		return nil, fmt.Errorf("timestamp body length %d not equal to 16", bodyLen)
	}
	p := &Timestamp{ID: int(b[0])<<8 | int(b[1]), Seq: int(b[2])<<8 | int(b[3])}

	parseInt := func(start int) uint32 {
		return uint32(b[start])<<24 |
			uint32(b[start+1])<<16 |
			uint32(b[start+2])<<8 |
			uint32(b[start+3])
	}

	p.OriginTimestamp = parseInt(originTimestamp)
	p.ReceiveTimestamp = parseInt(receiveTimestamp)
	p.TransmitTimestamp = parseInt(transmitTimestamp)

	return p, nil
}

// PingIcmpAddressMaskRequestAsync 异步发送 ICMP 地址掩码请求到指定的 IPv4 地址，ICMP 地址掩码请求是一种询问目标主机的子网掩码的 ICMP 类型请求
func PingIcmpAddressMaskRequestAsync(s *Scanner, ip string) {
	if !iputil.IsIPv4(ip) {
		return
	}
	destAddr := &net.IPAddr{IP: net.ParseIP(ip)}
	m := icmp.Message{
		Type: ipv4.ICMPType(17), // 17 表示是地址掩码请求
		Code: 0,
		Body: &AddressMask{
			ID:          os.Getpid() & 0xffff,
			Seq:         0,
			AddressMask: 0,
		},
	}

	data, err := m.Marshal(nil)
	if err != nil {
		return
	}
	retries := 0
send:
	if retries >= maxRetries {
		return
	}
	_, err = s.icmpPacketListener4.WriteTo(data, destAddr)
	if err != nil {
		retries++
		// 引入小延迟以允许网络接口刷新队列
		time.Sleep(time.Duration(DeadlineSec) * time.Millisecond)
		goto send
	}
}

// AddressMask ICMP structure
type AddressMask struct {
	ID          int
	Seq         int
	AddressMask uint32
}

const marshalledAddressMaskLen = 8

// Len 返回默认时间戳长度
func (a *AddressMask) Len(_ int) int {
	if a == nil {
		return 0
	}
	return marshalledAddressMaskLen
}

// Marshal 地址掩码结构
func (a *AddressMask) Marshal(_ int) ([]byte, error) {
	bSize := marshalledAddressMaskLen / 2
	b := make([]byte, marshalledAddressMaskLen)
	b[0], b[1] = byte(a.ID>>bSize), byte(a.ID)
	b[2], b[3] = byte(a.Seq>>bSize), byte(a.Seq)

	unparseInt := func(i uint32) (byte, byte, byte, byte) {
		bs := make([]byte, 4)
		binary.LittleEndian.PutUint32(bs, i)
		return bs[3], bs[2], bs[1], bs[0]
	}

	b[4], b[5], b[6], b[7] = unparseInt(a.AddressMask)
	return b, nil
}
