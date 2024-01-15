//go:build linux || darwin

package scanner

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"gitlab.example.com/zhangweijie/tool-sdk/middleware/logger"
	"net"
)

func init() {
	arpRequestAsyncCallback = ArpRequestAsync
}

// ArpRequestAsync 在给定的网络接口上异步发送 ARP 请求，确定与指定的 IPv4 地址关联的 MAC 地址
func ArpRequestAsync(s *Scanner, ip string) {
	networkInterface, _, sourceIP, err := s.Router.Route(net.ParseIP(ip))
	if networkInterface == nil {
		err = errors.New("Could not send ARP Request packet to " + ip + ": no interface with outbound source found")
	}
	if err != nil {
		return
	}
	// 定义以太网帧
	eth := layers.Ethernet{
		SrcMAC:       networkInterface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	// 定义 ARP 请求的具体字段
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
			err = handler.WritePacketData(buf.Bytes())
			if err != nil {
				logger.Warn(fmt.Sprintf("发送 ARP 请求出现问题, %s", err.Error()))
			}
		}
	}
}
