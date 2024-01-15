//go:build linux || darwin

package scanner

import (
	"errors"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

func init() {
	pingNdpRequestAsyncCallback = PingNdpRequestAsync
}

// PingNdpRequestAsync 异步发送 ICMP 的Echo Request 回声请求到指定的 IPv6 地址
func PingNdpRequestAsync(s *Scanner, ip string) {
	networkInterface, _, _, err := s.Router.Route(net.ParseIP(ip))
	if networkInterface == nil {
		err = errors.New("Could not send PingNdp Request packet to " + ip + ": no interface with outbound source found")
	}
	if err != nil {
		return
	}
	destAddr := &net.UDPAddr{IP: net.ParseIP(ip), Zone: networkInterface.Name}
	m := icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte(""),
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
	_, err = s.icmpPacketListener6.WriteTo(data, destAddr)
	if err != nil {
		retries++
		// 引入小延迟以允许网络接口刷新队列
		time.Sleep(time.Duration(DeadlineSec) * time.Millisecond)
		goto send
	}
}
