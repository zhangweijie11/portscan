//go:build linux || darwin

package scanner

import (
	"errors"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func init() {
	arpRequestAsyncCallback = ArpRequestAsync
}

// ArpRequestAsync 与目标 IP 地址异步
func ArpRequestAsync(s *Scanner, ip string) {
	networkInterface, _, sourceIP, err := s.Router.Route(net.ParseIP(ip))
	if networkInterface == nil {
		err = errors.New("Could not send ARP Request packet to " + ip + ": no interface with outbound source found")
	}
	if err != nil {
		return
	}
	// network layers
	eth := layers.Ethernet{
		SrcMAC:       networkInterface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(networkInterface.HardwareAddr),
		SourceProtAddress: sourceIP.To4(),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    net.ParseIP(ip).To4(),
	}

	// 设置缓冲区和序列化选项
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(buf, opts, &eth, &arp)
	if err != nil {
		return
	}
	// 在每个接口上发送数据包
	if handlers, ok := s.handlers.(Handlers); ok {
		for _, handler := range handlers.EthernetActive {
			err := handler.WritePacketData(buf.Bytes())
			if err != nil {
				continue
			}
		}
	}
}
