package scanner

import (
	"errors"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// Some constants
const (
	DeadlineSec      = 100
	ProtocolICMP     = 1
	ProtocolIPv6ICMP = 58
)

// PingResult contains the results for the Ping request
type PingResult struct {
	Hosts []Ping
}

// Ping contains the results for ping on a single host
type Ping struct {
	Type    PingResultType
	Latency time.Duration
	Error   error
	Host    string
}

// PingResultType contains the type of result for ping request on an address
type PingResultType int

// Type of ping responses
const (
	HostInactive PingResultType = iota
	HostActive
)

// PingHosts ping给定的地址并返回每个主机的延迟 如果地址返回错误，则该地址将标记为不可用
func PingHosts(addresses []string) (*PingResult, error) {
	// Start listening for icmp replies
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	defer c.Close()

	results := &PingResult{Hosts: []Ping{}}
	var sequence int

	for _, addr := range addresses {
		// 解析任何 DNS（如果使用）并获取目标的真实 IP
		dst, err := net.ResolveIPAddr("ip4", addr)
		if err != nil {
			results.Hosts = append(results.Hosts, Ping{Type: HostInactive, Error: err, Host: addr})
			continue
		}

		sequence++
		// Make a new ICMP message
		m := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{
				ID:   os.Getpid() & 0xffff,
				Seq:  sequence,
				Data: []byte(""),
			},
		}

		data, err := m.Marshal(nil)
		if err != nil {
			results.Hosts = append(results.Hosts, Ping{Type: HostInactive, Error: err, Host: addr})
			continue
		}

		// Send the packet
		start := time.Now()
		_, err = c.WriteTo(data, dst)
		if err != nil {
			results.Hosts = append(results.Hosts, Ping{Type: HostInactive, Error: err, Host: addr})
			continue
		}

		reply := make([]byte, 1500)
		err = c.SetReadDeadline(time.Now().Add(DeadlineSec * time.Second))
		if err != nil {
			results.Hosts = append(results.Hosts, Ping{Type: HostInactive, Error: err, Host: addr})
			continue
		}

		n, _, err := c.ReadFrom(reply)
		if err != nil {
			results.Hosts = append(results.Hosts, Ping{Type: HostInactive, Error: err, Host: addr})
			continue
		}
		duration := time.Since(start)

		rm, err := icmp.ParseMessage(ProtocolICMP, reply[:n])
		if err != nil {
			results.Hosts = append(results.Hosts, Ping{Type: HostInactive, Error: err, Host: addr})
			continue
		}
		switch rm.Type {
		case ipv4.ICMPTypeEchoReply:
			results.Hosts = append(results.Hosts, Ping{Type: HostActive, Latency: duration, Host: addr})
		default:
			results.Hosts = append(results.Hosts, Ping{Type: HostInactive, Error: errors.New("no reply found for ping probe"), Host: addr})
			continue
		}
	}

	return results, nil
}

// GetFastestHost 从 ping 响应中获取最快的主机
func (p *PingResult) GetFastestHost() (Ping, error) {
	var ping Ping

	// 如果当前主机的延迟小于所选主机，并且主机处于活动状态，使用延迟最小的主机。
	for _, host := range p.Hosts {
		if (host.Latency < ping.Latency || ping.Latency == 0) && host.Type == HostActive {
			ping.Type = HostActive
			ping.Latency = host.Latency
			ping.Host = host.Host
		}
	}

	if ping.Type != HostActive {
		return ping, errors.New("no active host found for target")
	}
	return ping, nil
}
