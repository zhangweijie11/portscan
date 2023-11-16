package portlist

import (
	"fmt"
	"gitlab.example.com/zhangweijie/portscan/services/pportscan/protocol"
)

type Port struct {
	Port     int
	Protocol protocol.Protocol
	TLS      bool
}

func (p *Port) String() string {
	return fmt.Sprintf("%d-%d-%v", p.Port, p.Protocol, p.TLS)
}
