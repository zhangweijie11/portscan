//go:build linux || darwin

package scanner

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/projectdiscovery/freeport"
	"github.com/projectdiscovery/utils/routing"
	"gitlab.example.com/zhangweijie/portscan/services/pportscan/portlist"
	"gitlab.example.com/zhangweijie/portscan/services/pportscan/protocol"
	"gitlab.example.com/zhangweijie/tool-sdk/middleware/logger"
	"golang.org/x/net/icmp"
	"io"
	"net"
	"sync"
	"time"
)

func init() {
	newScannerCallback = NewScannerUnix
	setupHandlerCallback = SetupHandlerUnix
	tcpReadWorkerPCAPCallback = TransportReadWorkerPCAPUnix
	cleanupHandlersCallback = CleanupHandlersUnix
}

// Handlers 包含 PCAP 处理程序的列表
type Handlers struct {
	LoopbackHandlers  []*pcap.Handle
	TransportActive   []*pcap.Handle
	TransportInactive []*pcap.InactiveHandle
	EthernetActive    []*pcap.Handle
	EthernetInactive  []*pcap.InactiveHandle
}

// 从操作系统获取随机端口
func getFreePort() (int, error) {
	rawPort, err := freeport.GetFreeTCPPort("")
	if err != nil {
		return 0, err
	}
	return rawPort.Port, nil
}

// NewScannerUnix 创建特定于 Unix 操作系统的扫描器
func NewScannerUnix(scanner *Scanner) error {
	if scanner.SourcePort <= 0 {
		rawport, err := getFreePort()
		if err != nil {
			return err
		}
		scanner.SourcePort = rawport
	}

	// 创建IPv4 的 TCP 网络连接监听器
	tcpConn4, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: net.ParseIP(fmt.Sprintf("0.0.0.0:%d", scanner.SourcePort))})
	if err != nil {
		return err
	}
	scanner.tcpPacketListener4 = tcpConn4

	// 创建IPv4 的 UDP 网络连接监听器
	udpConn4, err := net.ListenIP("ip4:udp", &net.IPAddr{IP: net.ParseIP(fmt.Sprintf("0.0.0.0:%d", scanner.SourcePort))})
	if err != nil {
		return err
	}
	scanner.udpPacketListener4 = udpConn4

	// 创建IPv4 的 ICMP 网络连接监听器，ICMP（Internet Control Message Protocol）监听器的作用在于监听和处理传入的 ICMP 数据包。 ICMP 是网络层协议，主要用于网络中的控制和错误消息。 ICMP 数据包通常用于报告网络的异常情况，例如主机不可达、超时等。
	icmpConn4, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return err
	}
	scanner.icmpPacketListener4 = icmpConn4

	// 创建IPv6 的 TCP 网络连接监听器
	tcpConn6, err := net.ListenIP("ip6:tcp", &net.IPAddr{IP: net.ParseIP(fmt.Sprintf(":::%d", scanner.SourcePort))})
	if err != nil {
		return err
	}
	scanner.tcpPacketListener6 = tcpConn6

	// 创建IPv6 的 UDP 网络连接监听器
	udpConn6, err := net.ListenIP("ip6:udp", &net.IPAddr{IP: net.ParseIP(fmt.Sprintf(":::%d", scanner.SourcePort))})
	if err != nil {
		return err
	}
	scanner.udpPacketListener6 = udpConn6

	// 创建IPv6 的 ICMP 网络连接监听器
	icmpConn6, err := icmp.ListenPacket("ip6:icmp", "::")
	if err != nil {
		return err
	}
	scanner.icmpPacketListener6 = icmpConn6

	var handlers Handlers
	scanner.handlers = handlers

	// 创建结果通道
	scanner.tcpChan = PkgResultChan{
		RWMutex:   sync.RWMutex{},
		PkgResult: make(chan *PkgResult, chanSize),
		closed:    false,
	}
	scanner.udpChan = PkgResultChan{
		RWMutex:   sync.RWMutex{},
		PkgResult: make(chan *PkgResult, chanSize),
		closed:    false,
	}
	scanner.hostDiscoveryChan = PkgResultChan{
		RWMutex:   sync.RWMutex{},
		PkgResult: make(chan *PkgResult, chanSize),
		closed:    false,
	}

	// 创建发送通道
	scanner.transportPacketSend = make(chan *PkgSend, packetSendSize)
	scanner.icmpPacketSend = make(chan *PkgSend, packetSendSize)
	scanner.ethernetPacketSend = make(chan *PkgSend, packetSendSize)

	// 创建路由引擎
	scanner.Router, err = routing.New()

	return err
}

// SetupHandlerUnix 根据不同协议类型创建和配置处理器，方便后续可以使用处理器来捕获和处理网络数据包
/*
InterfaceName：要捕获数据包的网络接口的名称
bpfFilter：BPF 过滤器，用于指定要捕获的数据包条件
protocols：要捕获的协议类型
*/
func SetupHandlerUnix(s *Scanner, interfaceName, bpfFilter string, protocols ...protocol.Protocol) error {
	// 现有只有三个协议，TCP，UDP 和 ARP
	for _, proto := range protocols {
		// 创建未激活的PCAP句柄（handle），可以在配置捕获选项后再激活句柄
		inactive, err := pcap.NewInactiveHandle(interfaceName)
		if err != nil {
			//s.CleanupHandlers()
			return err
		}
		// 设置捕获参数，包括快照长度snaplen 和读取超时 readtimeout，决定捕获数据包的行为
		err = inactive.SetSnapLen(snaplen)
		if err != nil {
			//s.CleanupHandlers()
			return err
		}

		// 数据包的读取超时时间
		readTimeout := time.Duration(readtimeout) * time.Millisecond
		if err = inactive.SetTimeout(readTimeout); err != nil {
			s.CleanupHandlers()
			return err
		}
		// 启用立即模式，方便数据包在捕获后立即可用
		err = inactive.SetImmediateMode(true)
		if err != nil {
			//s.CleanupHandlers()
			return err
		}

		handlers, ok := s.handlers.(Handlers)
		if !ok {
			//s.CleanupHandlers()
			return errors.New("无法创建处理器")
		}

		// 添加未激活句柄
		switch proto {
		case protocol.TCP, protocol.UDP:
			handlers.TransportInactive = append(handlers.TransportInactive, inactive)
		case protocol.ARP:
			handlers.EthernetInactive = append(handlers.EthernetInactive, inactive)
		default:
			logger.Warn("协议不支持")
		}

		// 激活之前创建的未激活的 PCAP 句柄
		handle, err := inactive.Activate()
		// 激活失败进行资源清理
		if err != nil {
			s.CleanupHandlers()
			return err
		}

		// 严格的BPF过滤器，确保只捕获满足条件的网络包
		err = handle.SetBPFFilter(bpfFilter)
		if err != nil {
			//s.CleanupHandlers()
			return err
		}
		iface, err := net.InterfaceByName(interfaceName)
		if err != nil {
			//s.CleanupHandlers()
			return err
		}

		// 添加激活句柄
		switch proto {
		case protocol.TCP, protocol.UDP:
			// 如果iface.Flags中包含回环标志（net.FlagLoopback），则添加处理器
			if iface.Flags&net.FlagLoopback == net.FlagLoopback {
				handlers.LoopbackHandlers = append(handlers.LoopbackHandlers, handle)
			} else {
				handlers.TransportActive = append(handlers.TransportActive, handle)
			}
		case protocol.ARP:
			handlers.EthernetActive = append(handlers.EthernetActive, handle)
		default:
			logger.Warn("协议不支持")
		}
		s.handlers = handlers
	}

	return nil
}

// TransportReadWorkerPCAPUnix 处理网络数据包的捕获和分析
func TransportReadWorkerPCAPUnix(s *Scanner) {
	// 清理未激活的句柄和激活的处理器
	defer s.CleanupHandlers()

	var wgread sync.WaitGroup

	handlers, ok := s.handlers.(Handlers)
	if !ok {
		return
	}

	// 处理传输层数据包
	transportReaderCallback := func(tcp layers.TCP, udp layers.UDP, ip, srcIP4, srcIP6 string) {
		// 只考虑传入的数据包
		tcpPortMatches := tcp.DstPort == layers.TCPPort(s.SourcePort)
		udpPortMatches := udp.DstPort == layers.UDPPort(s.SourcePort)
		sourcePortMatches := tcpPortMatches || udpPortMatches
		switch {
		case !sourcePortMatches:
			// 如果源端口不匹配，输出日志并丢弃数据包
			logger.Info(fmt.Sprintf("Discarding Transport packet from non target ips: ip4=%s ip6=%s tcp_dport=%d udp_dport=%d", srcIP4, srcIP6, tcp.DstPort, udp.DstPort))
		case s.Phase.Is(HostDiscovery):
			proto := protocol.TCP
			if udpPortMatches {
				proto = protocol.UDP
			}
			s.hostDiscoveryChan.Send(&PkgResult{ip: ip, port: &portlist.Port{Port: int(tcp.SrcPort), Protocol: proto}})
		case tcpPortMatches && tcp.SYN && tcp.ACK:
			// 如果是TCP数据包且目标端口匹配，并且同时设置了SYN和ACK标志，将结果发送到TCP通道
			s.tcpChan.Send(&PkgResult{ip: ip, port: &portlist.Port{Port: int(tcp.SrcPort), Protocol: protocol.TCP}})
		case udpPortMatches && udp.Length > 0: // 要更好地匹配 UDP 有效负载
			// 如果是UDP数据包且目标端口匹配，并且UDP数据包的长度大于0，将结果发送到UDP通道
			s.udpChan.Send(&PkgResult{ip: ip, port: &portlist.Port{Port: int(udp.SrcPort), Protocol: protocol.UDP}})
		}
	}

	loopBackScanCaseCallback := func(handler *pcap.Handle, wg *sync.WaitGroup) {
		defer wg.Done()
		// 基于 handler PCAP 处理器和链路类型 linktype 创建一个数据包源
		packetSource := gopacket.NewPacketSource(handler, handler.LinkType())
		for packet := range packetSource.Packets() {
			tcp := &layers.TCP{}
			udp := &layers.UDP{}
			// 从数据包中提取网络层（IPv4或IPv6）和传输层（TCP或UDP）的信息
			for _, layerType := range packet.Layers() {
				ipLayer := packet.Layer(layers.LayerTypeIPv4)
				if ipLayer == nil {
					ipLayer = packet.Layer(layers.LayerTypeIPv6)
					if ipLayer == nil {
						continue
					}
				}
				// 确定源 IP 地址
				var srcIP4, srcIP6 string
				if ipv4, ok := ipLayer.(*layers.IPv4); ok {
					srcIP4 = ipv4.SrcIP.String()
				} else if ipv6, ok := ipLayer.(*layers.IPv6); ok {
					srcIP6 = ipv6.SrcIP.String()
				}

				// 确定传输层类型
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer != nil {
					tcp, ok = tcpLayer.(*layers.TCP)
					if !ok {
						continue
					}
				}
				udpLayer := packet.Layer(layers.LayerTypeUDP)
				if udpLayer != nil {
					udp, ok = udpLayer.(*layers.UDP)
					if !ok {
						continue
					}
				}

				// 只有传输层协议为 TCP或 UDP 时才会继续处理
				if layerType.LayerType() == layers.LayerTypeTCP || layerType.LayerType() == layers.LayerTypeUDP {
					srcPort := fmt.Sprint(int(tcp.SrcPort))
					srcIP4WithPort := net.JoinHostPort(srcIP4, srcPort)
					isIP4InRange := s.IPRanger.ContainsAny(srcIP4, srcIP4WithPort)
					srcIP6WithPort := net.JoinHostPort(srcIP6, srcPort)
					isIP6InRange := s.IPRanger.ContainsAny(srcIP6, srcIP6WithPort)
					var ip string
					if isIP4InRange {
						ip = srcIP4
					} else if isIP6InRange {
						ip = srcIP6
					} else {
						logger.Info(fmt.Sprintf("Discarding Transport packet from non target ips: ip4=%s ip6=%s\n", srcIP4, srcIP6))
					}
					transportReaderCallback(*tcp, *udp, ip, srcIP4, srcIP6)
				}
			}
		}
	}

	for _, handler := range handlers.LoopbackHandlers {
		wgread.Add(1)
		go loopBackScanCaseCallback(handler, &wgread)
	}

	// 传输层读取器 （TCP|UDP），并发处理网络数据包
	for _, handler := range handlers.TransportActive {
		wgread.Add(1)
		go func(handler *pcap.Handle) {
			defer wgread.Done()

			var (
				eth layers.Ethernet
				ip4 layers.IPv4
				ip6 layers.IPv6
				tcp layers.TCP
				udp layers.UDP
			)

			// 带 MAC 的接口（物理 + 虚拟化）创建解析器
			parser4Mac := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp, &udp)
			parser6Mac := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip6, &tcp, &udp)
			// 不带 MAC 的接口 （TUNTAP）创建解析器
			parser4NoMac := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &tcp, &udp)
			parser6NoMac := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, &ip6, &tcp, &udp)

			// 应对不同网络接口类型可能存在的协议层变化
			var parsers []*gopacket.DecodingLayerParser
			parsers = append(parsers,
				parser4Mac, parser6Mac,
				parser4NoMac, parser6NoMac,
			)

			// 存储已解码协议层
			var decoded []gopacket.LayerType

			// 循环处理从 handler 中读取的数据包
			for {
				// 从 pcap 句柄读取的数据包，以及与该数据包关联的错误代码
				data, _, err := handler.ReadPacketData()
				if err == io.EOF {
					break
				} else if err != nil {
					continue
				}

				for _, parser := range parsers {
					err := parser.DecodeLayers(data, &decoded)
					if err != nil {
						continue
					}
					for _, layerType := range decoded {
						// 检查已解码的协议层是否为 TCP 或 UDP 协议
						if layerType == layers.LayerTypeTCP || layerType == layers.LayerTypeUDP {
							// 提取源端口和源 IP，构建带端口的IP 地址，查看 IP 地址是否在目标 IP 范围内
							srcPort := fmt.Sprint(int(tcp.SrcPort))
							srcIP4 := ip4.SrcIP.String()
							srcIP4WithPort := net.JoinHostPort(srcIP4, srcPort)
							isIP4InRange := s.IPRanger.ContainsAny(srcIP4, srcIP4WithPort)
							srcIP6 := ip6.SrcIP.String()
							srcIP6WithPort := net.JoinHostPort(srcIP6, srcPort)
							isIP6InRange := s.IPRanger.ContainsAny(srcIP6, srcIP6WithPort)
							var ip string
							if isIP4InRange {
								ip = srcIP4
							} else if isIP6InRange {
								ip = srcIP6
							} else {
								//logger.Info(fmt.Sprintf("Discarding Transport packet from non target ips: ip4=%s ip6=%s\n", srcIP4, srcIP6))
								continue
							}
							transportReaderCallback(tcp, udp, ip, srcIP4, srcIP6)
						}
					}
				}
			}
		}(handler)
	}

	// 以太网读卡器
	for _, handler := range handlers.EthernetActive {
		wgread.Add(1)
		go func(handler *pcap.Handle) {
			defer wgread.Done()

			var (
				eth layers.Ethernet
				arp layers.ARP
			)

			// 初始化以太网和 ARP 协议层解析
			parser4 := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &arp)
			// 忽略不支持的协议层
			parser4.IgnoreUnsupported = true
			var parsers []*gopacket.DecodingLayerParser
			parsers = append(parsers, parser4)

			// 存储已解码的协议层
			var decoded []gopacket.LayerType

			for {
				data, _, err := handler.ReadPacketData()
				if err == io.EOF {
					break
				} else if err != nil {
					continue
				}

				// 循环处理从 handler 中读取的数据包
				for _, parser := range parsers {
					err := parser.DecodeLayers(data, &decoded)
					if err != nil {
						continue
					}
					for _, layerType := range decoded {
						if layerType == layers.LayerTypeARP {
							// 检查数据包是否已发送出去，检查已解码的协议层是否为 ARP 协议
							isReply := arp.Operation == layers.ARPReply
							var sourceMacIsInterfaceMac bool
							if s.NetworkInterface != nil {
								sourceMacIsInterfaceMac = bytes.Equal([]byte(s.NetworkInterface.HardwareAddr), arp.SourceHwAddress)
							}
							isOutgoingPacket := !isReply || sourceMacIsInterfaceMac
							if isOutgoingPacket {
								continue
							}
							// 检查 ARP 数据包的操作码，判断是否为 ARP 回复
							srcIP4 := net.IP(arp.SourceProtAddress)
							//srcMac := net.HardwareAddr(arp.SourceHwAddress)

							isIP4InRange := s.IPRanger.Contains(srcIP4.String())

							// 提取 ARP 数据包中的源 IP 地址和源 MAC 地址，并检查源 IP 地址是否在目标 IP 范围内
							var ip string
							if isIP4InRange {
								ip = srcIP4.String()
							} else {
								//logger.Info(fmt.Sprintf("Discarding ARP packet from non target ip: ip4=%s mac=%s\n", srcIP4, srcMac))
								continue
							}

							s.hostDiscoveryChan.Send(&PkgResult{ip: ip})
						}
					}
				}
			}
		}(handler)
	}

	wgread.Wait()
}

// CleanupHandlersUnix 清理所有的处理器
func CleanupHandlersUnix(s *Scanner) {
	if handlers, ok := s.handlers.(Handlers); ok {
		for _, handler := range append(handlers.TransportActive, handlers.EthernetActive...) {
			handler.Close()
		}
		for _, inactiveHandler := range append(handlers.TransportInactive, handlers.EthernetInactive...) {
			inactiveHandler.CleanUp()
		}
	}
}
