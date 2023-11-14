package scanner

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/freeport"
	"github.com/projectdiscovery/ipranger"
	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/mapcidr/asn"
	"github.com/projectdiscovery/networkpolicy"
	"github.com/projectdiscovery/ratelimit"
	iputil "github.com/projectdiscovery/utils/ip"
	"github.com/projectdiscovery/utils/routing"
	"github.com/remeh/sizedwaitgroup"
	"gitlab.example.com/zhangweijie/portscan/global"
	"gitlab.example.com/zhangweijie/portscan/services/pportscan/portlist"
	"gitlab.example.com/zhangweijie/portscan/services/pportscan/privileges"
	"gitlab.example.com/zhangweijie/portscan/services/pportscan/protocol"
	"gitlab.example.com/zhangweijie/portscan/services/pportscan/result"
	"gitlab.example.com/zhangweijie/tool-sdk/middleware/logger"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

const (
	maxRetries     = 10
	sendDelayMsec  = 10
	chanSize       = 1000  //nolint
	packetSendSize = 2500  //nolint
	snaplen        = 65536 //nolint
	readtimeout    = 1500  //nolint
)

// PkgFlag  TCP 数据包标志
type PkgFlag int

const (
	Syn PkgFlag = iota
	Ack
	IcmpEchoRequest
	IcmpTimestampRequest
	IcmpAddressMaskRequest
	Arp
	Ndp
)

type Scanner struct {
	excludeCDN           bool   // 是否排除 CDN IP，默认为排除
	excludeWAF           bool   // 是否排除 WAF IP，默认为不排除
	excludeCloud         bool   // 是否排除 Cloud IP，默认为不排除
	Retries              int    // 端口扫描重试次数
	ScanType             string // 扫描模式，默认为 CONNECT，可选 SYN
	Phase                Phase
	Router               routing.Router
	SourceIP4            net.IP
	SourceIP6            net.IP
	SourcePort           int
	tcpPacketListener4   net.PacketConn
	udpPacketListener4   net.PacketConn
	icmpPacketListener4  net.PacketConn
	tcpPacketListener6   net.PacketConn
	udpPacketListener6   net.PacketConn
	icmpPacketListener6  net.PacketConn
	transportPacketSend  chan *PkgSend
	icmpPacketSend       chan *PkgSend
	ethernetPacketSend   chan *PkgSend
	tcpChan              chan *PkgResult
	udpChan              chan *PkgResult
	hostDiscoveryChan    chan *PkgResult
	Ports                []*portlist.Port
	IPRanger             *ipranger.IPRanger
	cdn                  *cdncheck.Client // 判断是否是 CDN 的客户端
	NetworkInterface     *net.Interface
	tcpsequencer         *TCPSequencer
	handlers             interface{} //nolint
	HostDiscoveryResults *result.PortScanResult
	ScanResults          *result.PortScanResult
	Limiter              *ratelimit.Limiter            // 控制单位时间内的发包数量
	WgScan               sizedwaitgroup.SizedWaitGroup // 控制协程并发数量
	serializeOptions     gopacket.SerializeOptions
}

// PkgSend 发送的 TCP 包
type PkgSend struct {
	ip       string
	port     *portlist.Port
	flag     PkgFlag
	SourceIP string
}

// PkgResult 数据包的结果
type PkgResult struct {
	ip   string
	port *portlist.Port
}

var (
	newScannerCallback                      func(s *Scanner) error
	setupHandlerCallback                    func(s *Scanner, interfaceName, bpfFilter string, protocols ...protocol.Protocol) error
	tcpReadWorkerPCAPCallback               func(s *Scanner)
	cleanupHandlersCallback                 func(s *Scanner)
	arpRequestAsyncCallback                 func(s *Scanner, ip string)
	pingIcmpEchoRequestCallback             func(ip string, timeout time.Duration) bool //nolint
	pingIcmpEchoRequestAsyncCallback        func(s *Scanner, ip string)
	pingIcmpTimestampRequestCallback        func(ip string, timeout time.Duration) bool //nolint
	pingIcmpTimestampRequestAsyncCallback   func(s *Scanner, ip string)
	pingIcmpAddressMaskRequestAsyncCallback func(s *Scanner, ip string)
	pingNdpRequestAsyncCallback             func(s *Scanner, ip string)
)

// NewScanner 初始化扫描器
func NewScanner(ctx context.Context, cdn, waf, cloud bool, scanType string) *Scanner {
	// 可通过集成 hmap 键值存储来追踪目标 IP，另外还继承了 mapcidr 库
	iprang, err := ipranger.New()
	if err != nil {
		return nil

	}
	var nPolicyOptions networkpolicy.Options
	nPolicy, err := networkpolicy.New(nPolicyOptions)
	if err != nil {
		return nil
	}
	iprang.Np = nPolicy
	scanner := &Scanner{
		excludeCDN:       cdn,
		excludeWAF:       waf,
		excludeCloud:     cloud,
		ScanType:         scanType,
		tcpsequencer:     NewTCPSequencer(),
		IPRanger:         iprang,
		serializeOptions: gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
	}

	// 不同的扫描模式，参数控制也不同
	if privileges.IsPrivileged && scanType == global.SynScan {
		scanner.Retries = global.DefaultRetriesSynScan
		// 控制协程并发数量
		scanner.WgScan = sizedwaitgroup.New(global.DefaultRateSynScan)
		// ratelimit 是一个用于限制请求速率的库。它提供了一种方便的方式来管理和控制在给定时间段内可以发送多少个请求。
		scanner.Limiter = ratelimit.New(ctx, uint(global.DefaultRateSynScan), time.Second)
	} else {
		scanner.Retries = global.DefaultRetriesConnectScan
		// 控制协程并发数量
		scanner.WgScan = sizedwaitgroup.New(global.DefaultRateConnectScan)
		// ratelimit 是一个用于限制请求速率的库。它提供了一种方便的方式来管理和控制在给定时间段内可以发送多少个请求。
		scanner.Limiter = ratelimit.New(ctx, uint(global.DefaultRateConnectScan), time.Second)
	}

	// 只要是需要排除 CDN/WAF/Cloud三者中的一个，就需要实例化检查器
	if scanner.excludeCDN || scanner.excludeWAF || scanner.excludeCloud {
		scanner.cdn = cdncheck.New()
	}
	scanner.ScanResults = result.NewPortScanResult()

	// 如果是 root 权限用户，提供回调函数
	if privileges.IsPrivileged && scanType == global.SynScan && newScannerCallback != nil {
		if err = newScannerCallback(scanner); err != nil {
			return nil
		}

	}
	return scanner
}

// CleanupHandlers 清理所有的接口
func (s *Scanner) CleanupHandlers() {
	if cleanupHandlersCallback != nil {
		cleanupHandlersCallback(s)
	}
}

// Close 关闭扫描程序实例
func (s *Scanner) Close() {
	_ = s.IPRanger.Hosts.Close()
	s.CleanupHandlers()
	s.tcpPacketListener4.Close()
	s.udpPacketListener4.Close()
	s.icmpPacketListener4.Close()
	s.tcpPacketListener6.Close()
	s.udpPacketListener6.Close()
	s.icmpPacketListener6.Close()
	close(s.transportPacketSend)
	close(s.icmpPacketSend)
	close(s.ethernetPacketSend)
	close(s.tcpChan)
	close(s.udpChan)
	close(s.hostDiscoveryChan)
}

// StartWorkers 后台执行任务
func (s *Scanner) StartWorkers() {
	//go s.ICMPReadWorker()
	//go s.ICMPWriteWorker()
	//go s.ICMPResultWorker()
	//go s.EthernetWriteWorker()

	// 构建和发送数据包
	go s.TransportWriteWorker()

	// 读取数据包的内容
	go s.TCPReadWorker4()
	go s.TCPReadWorker6()
	go s.UDPReadWorker4()
	go s.UDPReadWorker6()

	// 接收和解析数据包
	go s.TCPReadWorkerPCAP()

	// 处理结果
	go s.TCPResultWorker()
	go s.UDPResultWorker()

}

// ICMPReadWorker 启动 IP4 和 IP6 工作程序
func (s *Scanner) ICMPReadWorker() {
	go s.ICMPReadWorker4()
	go s.ICMPReadWorker6()
}

// ICMPReadWorker4 从网络层读取数据包
func (s *Scanner) ICMPReadWorker4() {
	defer s.icmpPacketListener4.Close()

	data := make([]byte, 1500)
	for {
		if s.Phase.Is(Done) {
			break
		}
		n, addr, err := s.icmpPacketListener4.ReadFrom(data)
		if err != nil {
			continue
		}

		if s.Phase.Is(Guard) {
			continue
		}

		rm, err := icmp.ParseMessage(ProtocolICMP, data[:n])
		if err != nil {
			continue
		}

		switch rm.Type {
		case ipv4.ICMPTypeEchoReply, ipv4.ICMPTypeTimestampReply:
			s.hostDiscoveryChan <- &PkgResult{ip: addr.String()}
		}
	}
}

// ICMPReadWorker6 网络层读取数据包
func (s *Scanner) ICMPReadWorker6() {
	defer s.icmpPacketListener6.Close()

	data := make([]byte, 1500)
	for {
		if s.Phase.Is(Done) {
			break
		}
		n, addr, err := s.icmpPacketListener6.ReadFrom(data)
		if err != nil {
			continue
		}

		if s.Phase.Is(Guard) {
			continue
		}

		rm, err := icmp.ParseMessage(ProtocolIPv6ICMP, data[:n])
		if err != nil {
			continue
		}

		switch rm.Type {
		case ipv6.ICMPTypeEchoReply:
			ip := addr.String()
			// check if it has [host]:port
			if ipSplit, _, err := net.SplitHostPort(ip); err == nil {
				ip = ipSplit
			}
			// drop zone
			if idx := strings.Index(ip, "%"); idx > 0 {
				ip = ip[:idx]
			}
			s.hostDiscoveryChan <- &PkgResult{ip: ip}
		}
	}
}

// ICMPWriteWorker 将数据包写入网络层
func (s *Scanner) ICMPWriteWorker() {
	for pkg := range s.icmpPacketSend {
		switch {
		case pkg.flag == IcmpEchoRequest && pingIcmpEchoRequestAsyncCallback != nil:
			pingIcmpEchoRequestAsyncCallback(s, pkg.ip)
		case pkg.flag == IcmpTimestampRequest && pingIcmpTimestampRequestAsyncCallback != nil:
			pingIcmpTimestampRequestAsyncCallback(s, pkg.ip)
		case pkg.flag == IcmpAddressMaskRequest && pingIcmpAddressMaskRequestAsyncCallback != nil:
			pingIcmpAddressMaskRequestAsyncCallback(s, pkg.ip)
		case pkg.flag == Ndp && pingNdpRequestAsyncCallback != nil:
			pingNdpRequestAsyncCallback(s, pkg.ip)
		}
	}
}

// ICMPResultWorker 处理 ICMP 响应（仅在探测期间使用）
func (s *Scanner) ICMPResultWorker() {
	for ip := range s.hostDiscoveryChan {
		if s.Phase.Is(HostDiscovery) {
			//logger.Info(fmt.Sprintf("Received ICMP response from %s\n", ip.ip))
			s.HostDiscoveryResults.AddIp(ip.ip)
		}
	}
}

// TCPReadWorker4 读取传入的 TCP 数据包
func (s *Scanner) TCPReadWorker4() {
	defer s.tcpPacketListener4.Close()
	// 创建一个大小为 4096 字节的缓冲区，用于存储从网络接口读取的数据包。
	data := make([]byte, 4096)
	for {
		if s.Phase.Is(Done) {
			break
		}
		// 将数据包内容存储在缓存区
		s.tcpPacketListener4.ReadFrom(data)
	}
}

// TCPReadWorker6 读取传入的 TCP 数据包
func (s *Scanner) TCPReadWorker6() {
	defer s.tcpPacketListener6.Close()
	data := make([]byte, 4096)
	for {
		if s.Phase.Is(Done) {
			break
		}
		// 将数据包内容存储在缓存区
		s.tcpPacketListener6.ReadFrom(data)
	}
}

// UDPReadWorker4 读取传入的 IPv4 UDP 数据包
func (s *Scanner) UDPReadWorker4() {
	defer s.udpPacketListener4.Close()
	data := make([]byte, 4096)
	for {
		if s.Phase.Is(Done) {
			break
		}
		// 将数据包内容存储在缓存区
		s.udpPacketListener4.ReadFrom(data)
	}
}

// UDPReadWorker6 读取传入的 ipv6 UDP 数据包
func (s *Scanner) UDPReadWorker6() {
	defer s.udpPacketListener6.Close()
	data := make([]byte, 4096)
	for {
		if s.Phase.Is(Done) {
			break
		}
		// 将数据包内容存储在缓存区
		s.udpPacketListener6.ReadFrom(data)
	}
}

// TCPReadWorkerPCAP 使用处理器读取和解析传入的 TCP 数据包
func (s *Scanner) TCPReadWorkerPCAP() {
	if tcpReadWorkerPCAPCallback != nil {
		tcpReadWorkerPCAPCallback(s)
	}
}

// TransportWriteWorker 发出TCP|UDP 数据包
func (s *Scanner) TransportWriteWorker() {
	for pkg := range s.transportPacketSend {
		s.SendAsyncPkg(pkg.ip, pkg.port, pkg.flag)
	}
}

// send 实现带有重试机制的发送数据包的功能，用于将序列化的网络层数据包发送到指定的目标 IP 地址
func (s *Scanner) send(destIP string, conn net.PacketConn, l ...gopacket.SerializableLayer) error {
	// 创建一个序列化缓冲区
	buf := gopacket.NewSerializeBuffer()
	// 使用 gopacket 库的 SerializeLayers 函数将层序列化到缓冲区
	if err := gopacket.SerializeLayers(buf, s.serializeOptions, l...); err != nil {
		return err
	}

	var (
		retries int
		err     error
	)

send:
	if retries >= maxRetries {
		return err
	}
	// 将序列化的数据包写入网络
	_, err = conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: net.ParseIP(destIP)})
	if err != nil {
		retries++
		// 引入小延迟以允许网络接口刷新队列
		time.Sleep(time.Duration(sendDelayMsec) * time.Millisecond)
		goto send
	}
	return err
}

// SendAsyncPkg 构建和发送 TCP 数据包，实现异步的 TCPv4 端口扫描
func (s *Scanner) SendAsyncPkg(ip string, p *portlist.Port, pkgFlag PkgFlag) {
	isIP4 := iputil.IsIPv4(ip)
	isIP6 := iputil.IsIPv6(ip)
	isTCP := p.Protocol == protocol.TCP
	isUDP := p.Protocol == protocol.UDP
	switch {
	case isIP4 && isTCP:
		s.sendAsyncTCP4(ip, p, pkgFlag)
	case isIP4 && isUDP:
		s.sendAsyncUDP4(ip, p)
	case isIP6 && isTCP:
		s.sendAsyncTCP6(ip, p, pkgFlag)
	case isIP6 && isUDP:
		s.sendAsyncUDP6(ip, p)
	}
}

func (s *Scanner) sendAsyncTCP4(ip string, p *portlist.Port, pkgFlag PkgFlag) {
	// 构建我们需要的所有网络层
	ip4 := layers.IPv4{
		DstIP:    net.ParseIP(ip),
		Version:  4,
		TTL:      255,
		Protocol: layers.IPProtocolTCP,
	}
	// 设置源 IP 地址，如果没有指定则使用路由器获取的源 IP 地址
	if s.SourceIP4 != nil {
		ip4.SrcIP = s.SourceIP4
	} else {
		_, _, sourceIP, err := s.Router.Route(ip4.DstIP)
		if err != nil {
			return
		} else if sourceIP == nil {
			return
		}
		ip4.SrcIP = sourceIP
	}

	// 构建 TCP 选项
	tcpOption := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x05, 0xB4},
	}

	// 构建 TCP 头部
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(s.SourcePort),
		DstPort: layers.TCPPort(p.Port),
		Window:  1024,
		Seq:     s.tcpsequencer.Next(),
		Options: []layers.TCPOption{tcpOption},
	}

	// 根据指定的标志设置 TCP 头部的标志位
	if pkgFlag == Syn {
		tcp.SYN = true
	} else if pkgFlag == Ack {
		tcp.ACK = true
	}

	// 设置 TCP 头部的校验和所需的网络层信息
	err := tcp.SetNetworkLayerForChecksum(&ip4)
	if err != nil {
		logger.Info(fmt.Sprintf("Can not set network layer for %s:%d port: %s\n", ip, p.Port, err))
	} else {
		err = s.send(ip, s.tcpPacketListener4, &tcp)
		if err != nil {
			logger.Info(fmt.Sprintf("Can not send packet to %s:%d port: %s\n", ip, p.Port, err))
		}
	}
}

func (s *Scanner) sendAsyncUDP4(ip string, p *portlist.Port) {
	// 构建我们需要的所有网络层
	ip4 := layers.IPv4{
		DstIP:    net.ParseIP(ip),
		Version:  4,
		TTL:      255,
		Protocol: layers.IPProtocolUDP,
	}
	if s.SourceIP4 != nil {
		ip4.SrcIP = s.SourceIP4
	} else {
		_, _, sourceIP, err := s.Router.Route(ip4.DstIP)
		if err != nil {
			return
		} else if sourceIP == nil {
			return
		}
		ip4.SrcIP = sourceIP
	}

	udp := layers.UDP{
		SrcPort: layers.UDPPort(s.SourcePort),
		DstPort: layers.UDPPort(p.Port),
	}

	err := udp.SetNetworkLayerForChecksum(&ip4)
	if err == nil {
		err = s.send(ip, s.udpPacketListener4, &udp)
		if err != nil {
			logger.Warn(fmt.Sprintf("Can not send packet to %s:%d port: %s\n", ip, p.Port, err))
		}
	}
}

func (s *Scanner) sendAsyncTCP6(ip string, p *portlist.Port, pkgFlag PkgFlag) {
	// 构建我们需要的所有网络层
	ip6 := layers.IPv6{
		DstIP:      net.ParseIP(ip),
		Version:    6,
		HopLimit:   255,
		NextHeader: layers.IPProtocolTCP,
	}

	if s.SourceIP6 != nil {
		ip6.SrcIP = s.SourceIP6
	} else {
		_, _, sourceIP, err := s.Router.Route(ip6.DstIP)
		if err != nil {
			return
		} else if sourceIP == nil {
			return
		}
		ip6.SrcIP = sourceIP
	}

	tcpOption := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x05, 0xB4},
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(s.SourcePort),
		DstPort: layers.TCPPort(p.Port),
		Window:  1024,
		Seq:     s.tcpsequencer.Next(),
		Options: []layers.TCPOption{tcpOption},
	}

	if pkgFlag == Syn {
		tcp.SYN = true
	} else if pkgFlag == Ack {
		tcp.ACK = true
	}

	err := tcp.SetNetworkLayerForChecksum(&ip6)
	if err == nil {
		err = s.send(ip, s.tcpPacketListener6, &tcp)
		if err != nil {
			logger.Info(fmt.Sprintf("Can not send packet to %s:%d port: %s\n", ip, p.Port, err))
		}
	}
}

func (s *Scanner) sendAsyncUDP6(ip string, p *portlist.Port) {
	// 构建我们需要的所有网络层
	ip6 := layers.IPv6{
		DstIP:      net.ParseIP(ip),
		Version:    6,
		HopLimit:   255,
		NextHeader: layers.IPProtocolUDP,
	}

	if s.SourceIP6 != nil {
		ip6.SrcIP = s.SourceIP6
	} else {
		_, _, sourceIP, err := s.Router.Route(ip6.DstIP)
		if err != nil {
			return
		} else if sourceIP == nil {
			return
		}
		ip6.SrcIP = sourceIP
	}

	udp := layers.UDP{
		SrcPort: layers.UDPPort(s.SourcePort),
		DstPort: layers.UDPPort(p.Port),
	}

	err := udp.SetNetworkLayerForChecksum(&ip6)
	if err == nil {
		err = s.send(ip, s.udpPacketListener6, &udp)
		if err != nil {
			logger.Info(fmt.Sprintf("Can not send packet to %s:%d port: %s\n", ip, p.Port, err))
		}
	}
}

// TCPResultWorker 处理 TCP 扫描结果
func (s *Scanner) TCPResultWorker() {
	for ip := range s.tcpChan {
		if s.Phase.Is(HostDiscovery) {
			//logger.Info(fmt.Sprintf("Received Transport (TCP|UDP) probe response from %s:%d\n", ip.ip, ip.port.Port))
			s.HostDiscoveryResults.AddIp(ip.ip)
		} else if s.Phase.Is(Scan) {
			//logger.Info(fmt.Sprintf("Received Transport (TCP) scan response from %s:%d\n", ip.ip, ip.port.Port))
			s.ScanResults.AddPort(ip.ip, ip.port)
		}
	}
}

// UDPResultWorker 处理 UDP 扫描结果
func (s *Scanner) UDPResultWorker() {
	for ip := range s.udpChan {
		if s.Phase.Is(HostDiscovery) {
			//logger.Info(fmt.Sprintf("Received UDP probe response from %s:%d\n", ip.ip, ip.port.Port))
			s.HostDiscoveryResults.AddIp(ip.ip)
		} else if s.Phase.Is(Scan) {
			//logger.Info(fmt.Sprintf("Received Transport (UDP) scan response from %s:%d\n", ip.ip, ip.port.Port))
			s.ScanResults.AddPort(ip.ip, ip.port)
		}
	}
}

// EthernetWriteWorker 将数据包写入网络层
func (s *Scanner) EthernetWriteWorker() {
	for pkg := range s.ethernetPacketSend {
		switch {
		case pkg.flag == Arp && arpRequestAsyncCallback != nil:
			arpRequestAsyncCallback(s, pkg.ip)
		}
	}
}

// canIScanIfCDN  如果需要继续扫描返回 True，不需要返回 False
func (s *Scanner) canIScanIfCDN(ip string) (ipType string, isContinue bool) {
	// 不对 IP 进行任何判断则需要继续扫描
	if !s.excludeCDN && !s.excludeWAF && !s.excludeCloud {
		return "other", true
	}

	matched, _, itemType, err := s.cdn.Check(net.ParseIP(ip))
	// 判断该 IP 不属于 CDN IP, 需要继续扫描
	if err == nil && !matched {
		return "other", true
	}

	// 需要排除 CDN IP，并且目标 IP 就是 CDN IP
	if s.excludeCDN && itemType == "cdn" {
		return itemType, false
	}

	// 需要排除 WAF IP，并且目标 IP 就是 WAF IP
	if s.excludeWAF && itemType == "waf" {
		return itemType, false
	}

	// 需要排除 Cloud IP，并且目标 IP 就是 Cloud IP
	if s.excludeCloud && itemType == "cloud" {
		return itemType, false
	}

	return "other", true
}

// SetupHandler 监听指定的接口
func (s *Scanner) SetupHandler(interfaceName string) error {
	// 构建 BPF 过滤器
	bpfFilter := fmt.Sprintf("dst port %d and (tcp or udp)", s.SourcePort)
	// 执行回调函数
	if setupHandlerCallback != nil {
		err := setupHandlerCallback(s, interfaceName, bpfFilter, protocol.TCP)
		if err != nil {
			return err
		}
	}
	// TODO：ARP 主要用来进行主机发现
	//arp filter should be improved with source mac
	// https://stackoverflow.com/questions/40196549/bpf-expression-to-capture-only-arp-reply-packets
	// (arp[6:2] = 2) and dst host host and ether dst mac
	// 设置 arp 过滤器
	//bpfFilter = "arp"
	//// 执行回调函数
	//if setupHandlerCallback != nil {
	//	err := setupHandlerCallback(s, interfaceName, bpfFilter, protocol.ARP)
	//	if err != nil {
	//		return err
	//	}
	//}

	return nil
}

// SetupHandlers 监听所有的接口
func (s *Scanner) SetupHandlers() error {
	if s.NetworkInterface != nil {
		return s.SetupHandler(s.NetworkInterface.Name)
	}

	// 手动监听所有接口
	itfs, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, itf := range itfs {
		// 检查网络接口是否处于启用状态，如果网络接口状态为 Down（FlagUp == 0），则跳过对该接口的处理
		isInterfaceDown := itf.Flags&net.FlagUp == 0
		if isInterfaceDown {
			continue
		}
		if err = s.SetupHandler(itf.Name); err != nil {
			logger.Warn(fmt.Sprintf("Error on interface %s: %s", itf.Name, err))
		}
	}

	return nil
}

// EnqueueICMP 传出 ICMP 数据包
func (s *Scanner) EnqueueICMP(ip string, pkgtype PkgFlag) {
	s.icmpPacketSend <- &PkgSend{
		ip:   ip,
		flag: pkgtype,
	}
}

// EnqueueEthernet 传出以太网数据包
func (s *Scanner) EnqueueEthernet(ip string, pkgtype PkgFlag) {
	s.ethernetPacketSend <- &PkgSend{
		ip:   ip,
		flag: pkgtype,
	}
}

// ScanSyn 扫描目标 IP
func (s *Scanner) ScanSyn(ip string) {
	for _, port := range s.Ports {
		s.EnqueueTCP(ip, Syn, port)
	}
}

// GetInterfaceFromIP 从本地 IP 地址获取网络接口的名称
func GetInterfaceFromIP(ip net.IP) (*net.Interface, error) {
	address := ip.String()

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, i := range interfaces {
		byNameInterface, err := net.InterfaceByName(i.Name)
		if err != nil {
			return nil, err
		}

		addresses, err := byNameInterface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, v := range addresses {
			// 检查当前接口的 IP 是否为我们的源 IP。如果是，则返回接口
			if strings.HasPrefix(v.String(), address+"/") {
				return byNameInterface, nil
			}
		}
	}

	return nil, fmt.Errorf("no interface found for ip %s", address)
}

// ConnectPort 单个主机和端口建立连接
func (s *Scanner) ConnectPort(host string, p *portlist.Port, timeout time.Duration) (bool, error) {
	hostport := net.JoinHostPort(host, fmt.Sprint(p.Port))
	var (
		err  error
		conn net.Conn
	)
	conn, err = net.DialTimeout(p.Protocol.String(), hostport, timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	// udp needs data probe
	switch p.Protocol {
	case protocol.UDP:
		if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			return false, err
		}
		if _, err := conn.Write(nil); err != nil {
			return false, err
		}
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return false, err
		}
		n, err := io.Copy(io.Discard, conn)
		// ignore timeout errors
		if err != nil && !os.IsTimeout(err) {
			return false, err
		}
		return n > 0, nil
	}

	return true, err
}

// ACKPort 将 ACK 数据包发送到端口
func (s *Scanner) ACKPort(dstIP string, port int, timeout time.Duration) (bool, error) {
	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return false, err
	}
	defer conn.Close()

	rawPort, err := freeport.GetFreeTCPPort("")
	if err != nil {
		return false, err
	}

	// Construct all the network layers we need.
	ip4 := layers.IPv4{
		DstIP:    net.ParseIP(dstIP),
		Version:  4,
		TTL:      255,
		Protocol: layers.IPProtocolTCP,
	}

	if s.SourceIP4 != nil {
		ip4.SrcIP = s.SourceIP4
	} else if s.Router != nil {
		_, _, sourceIP, err := s.Router.Route(ip4.DstIP)
		if err != nil {
			return false, err
		}
		ip4.SrcIP = sourceIP
	} else {
		return false, errors.New("could not find routes")
	}

	tcpOption := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x12, 0x34},
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(rawPort.Port),
		DstPort: layers.TCPPort(port),
		ACK:     true,
		Window:  1024,
		Seq:     s.tcpsequencer.Next(),
		Options: []layers.TCPOption{tcpOption},
	}

	err = tcp.SetNetworkLayerForChecksum(&ip4)
	if err != nil {
		return false, err
	}

	err = s.send(dstIP, conn, &tcp)
	if err != nil {
		return false, err
	}

	data := make([]byte, 4096)
	for {
		n, addr, err := conn.ReadFrom(data)
		if err != nil {
			break
		}

		// not matching ip
		if addr.String() != dstIP {
			continue
		}

		packet := gopacket.NewPacket(data[:n], layers.LayerTypeTCP, gopacket.Default)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, ok := tcpLayer.(*layers.TCP)
			if !ok {
				continue
			}
			//只考虑传入的数据包
			if tcp.DstPort != layers.TCPPort(rawPort.Port) {
				continue
			} else if tcp.RST {
				return true, nil
			}
		}
	}

	return false, nil
}

// EnqueueTCP 传出 TCP 数据包
func (s *Scanner) EnqueueTCP(ip string, pkgtype PkgFlag, ports ...*portlist.Port) {
	for _, port := range ports {
		s.transportPacketSend <- &PkgSend{
			ip:   ip,
			port: port,
			flag: pkgtype,
		}
	}
}

// EnqueueUDP 传出 UDP 数据包
func (s *Scanner) EnqueueUDP(ip string, ports ...*portlist.Port) {
	for _, port := range ports {
		s.transportPacketSend <- &PkgSend{
			ip:   ip,
			port: port,
		}
	}
}

// GetPreprocessedIps 获取等待处理的 IP
func (s *Scanner) GetPreprocessedIps() (ips []*net.IPNet, ipStatus map[string]string) {
	s.IPRanger.Hosts.Scan(func(ip, _ []byte) error {
		ipType, isContinue := s.canIScanIfCDN(string(ip))
		ipStatus = make(map[string]string)
		ipStatus[string(ip)] = ipType
		if isContinue {
			if cidr := iputil.ToCidr(string(ip)); cidr != nil {
				ips = append(ips, cidr)
			}
		}
		return nil
	})
	return
}

func (s *Scanner) GetTargetIps(ipsCallback func() ([]*net.IPNet, map[string]string)) (ipStatus map[string]string, targets, targetsV4, targetsv6 []*net.IPNet, err error) {
	targets, ipStatus = ipsCallback()

	// 将 IP 缩小到最少的 CIDR 量
	targetsV4, targetsv6 = mapcidr.CoalesceCIDRs(targets)
	if len(targetsV4) == 0 && len(targetsv6) == 0 {
		return nil, nil, nil, nil, errors.New("no valid ipv4 or ipv6 targets were found")
	}
	return ipStatus, targets, targetsV4, targetsv6, nil
}

// SplitAndParseIP  切割解析 IP
func (s *Scanner) SplitAndParseIP(targetIps []string) error {
	for _, oldIp := range targetIps {
		if asn.IsASN(oldIp) {
			// 获取针对 ASN 的 CIDR
			cidrs, err := asn.GetCIDRsForASNNum(oldIp)
			if err != nil {
				return fmt.Errorf("无效的 IP 列表: %s", oldIp)
			}
			for _, cidr := range cidrs {
				err = s.IPRanger.AddHostWithMetadata(cidr.String(), "cidr")
				if err != nil { // Add cidr directly to ranger, as single ips would allocate more resources later
					return fmt.Errorf("无效的 IP 列表: %s", oldIp)
				}
			}
		}
		if iputil.IsCIDR(oldIp) {
			if err := s.IPRanger.AddHostWithMetadata(oldIp, "cidr"); err != nil { // Add cidr directly to ranger, as single ips would allocate more resources later
				return fmt.Errorf("无效的 IP 列表: %s", oldIp)
			}
		}
		if iputil.IsIP(oldIp) && !s.IPRanger.Contains(oldIp) {
			ip := net.ParseIP(oldIp)
			// 将表示为 IP6 的 IP4 转换回 IP4
			if ip.To4() != nil {
				oldIp = ip.To4().String()
			}

			err := s.IPRanger.AddHostWithMetadata(oldIp, "ip")
			if err != nil {
				return fmt.Errorf("无效的 IP 列表: %s", oldIp)
			}
		}
	}

	return nil
}

// PickIP 根据给定的索引值从一组 IP 地址范围中选择一个具体的 IP 地址
func (s *Scanner) PickIP(targets []*net.IPNet, index int64) string {
	for _, target := range targets {
		// 获取当前子网中的 IP 地址总数
		subnetIpsCount := int64(mapcidr.AddressCountIpnet(target))
		// 如果目标索引在当前子网范围内，则选择该子网中的 IP
		if index < subnetIpsCount {
			return s.PickSubnetIP(target, index)
		}
		// 更新目标索引，减去当前子网中的 IP 地址总数
		index -= subnetIpsCount
	}

	return ""
}

// PickSubnetIP 选择 IP
func (s *Scanner) PickSubnetIP(network *net.IPNet, index int64) string {
	// 将子网的 IP 地址转换为整数表示
	ipInt, bits, err := mapcidr.IPToInteger(network.IP)
	if err != nil {
		return ""
	}
	// 使用大整数操作，计算子网中的目标 IP 地址的整数表示
	subnetIpInt := big.NewInt(0).Add(ipInt, big.NewInt(index))
	// 将整数表示的 IP 转换为字符串表示
	ip := mapcidr.IntegerToIP(subnetIpInt, bits)
	return ip.String()
}

// PickPort 选择端口
func (s *Scanner) PickPort(index int) *portlist.Port {
	return s.Ports[index]
}

// SimplePortScan 简单的端口扫描
func (s *Scanner) SimplePortScan(ip string, port *portlist.Port, timeout time.Duration) (bool, error) {
	hostPort := net.JoinHostPort(ip, fmt.Sprint(port.Port))

	conn, err := net.DialTimeout(port.Protocol.String(), hostPort, timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	switch port.Protocol {
	case protocol.UDP:
		if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			return false, err
		}
		if _, err := conn.Write(nil); err != nil {
			return false, err
		}
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return false, err
		}
		n, _ := io.Copy(io.Discard, conn)
		// ignore timeout errors
		if err != nil && !os.IsTimeout(err) {
			return false, err
		}
		return n > 0, nil
	}

	return true, nil
}

// ScanOpenPort  扫描开放端口
func (s *Scanner) ScanOpenPort(ip string, port *portlist.Port) {
	defer s.WgScan.Done()

	// 如果结果中存在该 IP 和端口则直接跳过
	if s.ScanResults.IPHasPort(ip, port) {
		return
	}

	s.Limiter.Take()
	defer func() {
		if err := recover(); err != nil {
			logger.Warn(fmt.Sprintf("信息侦测过程中的端口扫描捕获到错误: %s", err))
			return
		}
	}()
	// 简单的端口扫描，获取开放端口，然后进行服务识别和指纹识别
	open, err := s.SimplePortScan(ip, port, time.Duration(global.DefaultPortTimeoutConnectScan)*time.Millisecond)
	if open && err == nil {
		s.ScanResults.AddPort(ip, port)
	}
}

// RawSocketEnumeration  通过原始套接字获取开放端口
func (s *Scanner) RawSocketEnumeration(ip string, p *portlist.Port) {
	s.Limiter.Take()
	switch p.Protocol {
	case protocol.TCP:
		s.EnqueueTCP(ip, Syn, p)
	case protocol.UDP:
		s.EnqueueUDP(ip, p)
	}
}
