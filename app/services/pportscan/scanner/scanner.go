package scanner

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/gologger"
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
	"gitlab.example.com/zhangweijie/portscan/services/pportscan/tcpsequencer"
	"gitlab.example.com/zhangweijie/tool-sdk/middleware/logger"
	"io"
	"math/big"
	"net"
	"os"
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
)

type Scanner struct {
	Router              routing.Router
	SourceIP4           net.IP
	SourceIP6           net.IP
	SourcePort          int
	tcpPacketListener4  net.PacketConn
	udpPacketListener4  net.PacketConn
	tcpPacketListener6  net.PacketConn
	udpPacketListener6  net.PacketConn
	transportPacketSend chan *PkgSend
	WgScan              sizedwaitgroup.SizedWaitGroup // 控制协程并发数量
	Limiter             *ratelimit.Limiter            // 控制单位时间内的发包数量
	Ports               []*portlist.Port
	IPRanger            *ipranger.IPRanger
	cdn                 *cdncheck.Client // 判断是否是 CDN 的客户端
	excludeCDN          bool             // 是否排除 CDN IP，默认为排除
	excludeWAF          bool             // 是否排除 WAF IP，默认为不排除
	excludeCloud        bool             // 是否排除 Cloud IP，默认为不排除
	Retries             int              // 端口扫描重试次数
	ScanType            string           // 扫描模式，默认为 CONNECT，可选 SYN
	NetworkInterface    *net.Interface
	tcpsequencer        *tcpsequencer.TCPSequencer
	serializeOptions    gopacket.SerializeOptions
	tcpChan             chan *PkgResult
	udpChan             chan *PkgResult
	handlers            interface{} //nolint
	ScanResults         *result.PortScanResult
}

// PkgSend 发送的 TCP 包
type PkgSend struct {
	ip       string
	port     *portlist.Port
	flag     PkgFlag
	SourceIP string
}

// PkgResult 发送 TCP 包的结果
type PkgResult struct {
	ip   string
	port *portlist.Port
}

var (
	newScannerCallback        func(s *Scanner) error
	setupHandlerCallback      func(s *Scanner, interfaceName, bpfFilter string, protocols ...protocol.Protocol) error
	tcpReadWorkerPCAPCallback func(s *Scanner)
	cleanupHandlersCallback   func(s *Scanner)
)

// NewScanner 初始化扫描器
func NewScanner(ctx context.Context, cdn, waf, cloud bool, scanType string) *Scanner {
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
		tcpsequencer:     tcpsequencer.NewTCPSequencer(),
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
	if privileges.IsPrivileged && newScannerCallback != nil {
		if err = newScannerCallback(scanner); err != nil {
			return nil
		}

	}
	return scanner
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
	bpfFilter := fmt.Sprintf("dst port %d and (tcp or udp)", s.SourcePort)
	if setupHandlerCallback != nil {
		err := setupHandlerCallback(s, interfaceName, bpfFilter, protocol.TCP)
		if err != nil {
			return err
		}
	}
	// arp filter should be improved with source mac
	// https://stackoverflow.com/questions/40196549/bpf-expression-to-capture-only-arp-reply-packets
	// (arp[6:2] = 2) and dst host host and ether dst mac
	bpfFilter = "arp"
	if setupHandlerCallback != nil {
		err := setupHandlerCallback(s, interfaceName, bpfFilter, protocol.ARP)
		if err != nil {
			return err
		}
	}

	return nil
}

// SetupHandlers 监听所有的接口
func (s *Scanner) SetupHandlers() error {
	if s.NetworkInterface != nil {
		return s.SetupHandler(s.NetworkInterface.Name)
	}

	// 手动侦听所有接口
	itfs, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, itf := range itfs {
		isInterfaceDown := itf.Flags&net.FlagUp == 0
		if isInterfaceDown {
			continue
		}
		if err := s.SetupHandler(itf.Name); err != nil {
			gologger.Warning().Msgf("Error on interface %s: %s", itf.Name, err)
		}
	}

	return nil
}

// CleanupHandlers 清理所有的接口
func (s *Scanner) CleanupHandlers() {
	if cleanupHandlersCallback != nil {
		cleanupHandlersCallback(s)
	}
}

// StartWorkers 后台执行任务
func (s *Scanner) StartWorkers() {
	go s.TransportWriteWorker()
	go s.TCPReadWorkerPCAP()
	go s.TCPResultWorker()
	go s.UDPResultWorker()
}

// TCPReadWorkerPCAP 使用 pcap 读取和解析传入的 TCP 数据包
func (s *Scanner) TCPReadWorkerPCAP() {
	if tcpReadWorkerPCAPCallback != nil {
		tcpReadWorkerPCAPCallback(s)
	}
}

// TCPResultWorker 处理探针和扫描结果
func (s *Scanner) TCPResultWorker() {
	for ip := range s.tcpChan {
		s.ScanResults.AddPort(ip.ip, ip.port)
	}
}

// UDPResultWorker 处理探针和扫描结果
func (s *Scanner) UDPResultWorker() {
	for ip := range s.udpChan {
		s.ScanResults.AddPort(ip.ip, ip.port)
	}
}

// TransportWriteWorker 发出TCP|UDP 数据包
func (s *Scanner) TransportWriteWorker() {
	for pkg := range s.transportPacketSend {
		s.SendAsyncPkg(pkg.ip, pkg.port, pkg.flag)
	}
}

// SendAsyncPkg 将单个数据包发送到指定端口
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

	err := tcp.SetNetworkLayerForChecksum(&ip4)
	if err != nil {

	} else {
		err = s.send(ip, s.tcpPacketListener4, &tcp)
		if err != nil {
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
	if err != nil {
	} else {
		err = s.send(ip, s.tcpPacketListener6, &tcp)
		if err != nil {
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
			gologger.Debug().Msgf("Can not send packet to %s:%d port: %s\n", ip, p.Port, err)
		}
	}
}

// send 将给定的层作为网络上的单个数据包发送
func (s *Scanner) send(destIP string, conn net.PacketConn, l ...gopacket.SerializableLayer) error {
	buf := gopacket.NewSerializeBuffer()
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
	_, err = conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: net.ParseIP(destIP)})
	if err != nil {
		retries++
		// 引入小延迟以允许网络接口刷新队列
		time.Sleep(time.Duration(sendDelayMsec) * time.Millisecond)
		goto send
	}
	return err
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
			ips = append(ips, iputil.ToCidr(string(ip)))
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

// PickIP 选择 IP
func (s *Scanner) PickIP(targets []*net.IPNet, index int64) string {
	for _, target := range targets {
		subnetIpsCount := int64(mapcidr.AddressCountIpnet(target))
		if index < subnetIpsCount {
			return s.PickSubnetIP(target, index)
		}
		index -= subnetIpsCount
	}

	return ""
}

// PickSubnetIP 选择 IP
func (s *Scanner) PickSubnetIP(network *net.IPNet, index int64) string {
	ipInt, bits, err := mapcidr.IPToInteger(network.IP)
	if err != nil {
		gologger.Warning().Msgf("%s\n", err)
		return ""
	}
	subnetIpInt := big.NewInt(0).Add(ipInt, big.NewInt(index))
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

// Close 关闭扫描程序实例
func (s *Scanner) Close() {
	_ = s.IPRanger.Hosts.Close()
}
