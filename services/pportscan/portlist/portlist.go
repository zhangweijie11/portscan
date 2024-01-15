package portlist

import (
	"fmt"
	"gitlab.example.com/zhangweijie/portscan/services/pportscan/protocol"
	"strconv"
	"strings"
)

const portListStrParts = 2

type Port struct {
	Port     int
	Protocol protocol.Protocol
	TLS      bool
}

func (p *Port) String() string {
	return fmt.Sprintf("%d-%d-%v", p.Port, p.Protocol, p.TLS)
}

func ParsePortsSlice(ranges []string) ([]*Port, error) {
	var ports []*Port
	for _, r := range ranges {
		r = strings.TrimSpace(r)

		portProtocol := protocol.TCP
		if strings.HasPrefix(r, "u:") {
			portProtocol = protocol.UDP
			r = strings.TrimPrefix(r, "u:")
		}

		if strings.Contains(r, "-") {
			parts := strings.Split(r, "-")
			if len(parts) != portListStrParts {
				return nil, fmt.Errorf("invalid port selection segment: '%s'", r)
			}

			p1, err := strconv.Atoi(parts[0])
			if err != nil {
				return nil, fmt.Errorf("invalid port number: '%s'", parts[0])
			}

			p2, err := strconv.Atoi(parts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid port number: '%s'", parts[1])
			}

			if p1 > p2 {
				return nil, fmt.Errorf("invalid port range: %d-%d", p1, p2)
			}

			for i := p1; i <= p2; i++ {
				port := &Port{Port: i, Protocol: portProtocol}
				ports = append(ports, port)
			}
		} else {
			portNumber, err := strconv.Atoi(r)
			if err != nil {
				return nil, fmt.Errorf("invalid port number: '%s'", r)
			}
			port := &Port{Port: portNumber, Protocol: portProtocol}
			ports = append(ports, port)
		}
	}

	// dedupe ports
	seen := make(map[string]struct{})
	var dedupedPorts []*Port
	for _, port := range ports {
		if _, ok := seen[port.String()]; ok {
			continue
		}
		seen[port.String()] = struct{}{}
		dedupedPorts = append(dedupedPorts, port)
	}

	return dedupedPorts, nil
}
