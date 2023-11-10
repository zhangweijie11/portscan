package scanner

import (
	"fmt"
	"net"
	"time"

	"gitlab.example.com/zhangweijie/portscan/services/pportscan/portlist"
)

// ConnectVerify 使用连接请求验证端口是否准确
func (s *Scanner) ConnectVerify(host string, ports []*portlist.Port) []*portlist.Port {
	var verifiedPorts []*portlist.Port
	for _, p := range ports {
		conn, err := net.DialTimeout(p.Protocol.String(), fmt.Sprintf("%s:%d", host, p.Port), 3*time.Second)
		if err != nil {
			continue
		}
		conn.Close()
		verifiedPorts = append(verifiedPorts, p)
	}
	return verifiedPorts
}
