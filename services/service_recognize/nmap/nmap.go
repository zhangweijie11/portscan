package nmap

import (
	"fmt"
	"github.com/miekg/dns"
	"gitlab.example.com/zhangweijie/portscan/services/service_recognize/fingerprint"
	"gitlab.example.com/zhangweijie/portscan/services/service_recognize/portlist"
	"gitlab.example.com/zhangweijie/portscan/services/service_recognize/result"
	"strings"
	"time"
)

type Nmap struct {
	excludePort        portlist.PortList // 排除的端口列表
	portProbeMap       map[int]ProbeList //端口和探针名称列表的映射
	probeNameMap       map[string]*Probe //探针名称和探针的映射
	probeSort          ProbeList         //排序后的探针列表
	probeUsed          ProbeList         //已使用探针列表
	portService        map[int]string    //端口和服务的映射
	bypassAllProbePort portlist.PortList //需要绕过的端口列表
	sslSecondProbeMap  ProbeList
	allProbeMap        ProbeList
	sslProbeMap        ProbeList
	filter             int
	timeout            time.Duration //检测端口存活的超时时间
}

// NewNmap 初始化 Nmap 程序
func NewNmap() (nmap *Nmap) {
	// 初始化Nmap服务识别探针库
	nmapServiceProbes := RepairNmapString()
	// 自定义服务识别探针
	nmapCustomizeProbes := NmapCustomizeProbes
	nmap = &Nmap{
		excludePort:        portlist.EmptyPortList,
		probeNameMap:       make(map[string]*Probe),
		probeSort:          []string{},
		portProbeMap:       make(map[int]ProbeList),
		portService:        PortService,
		probeUsed:          emptyProbeList,
		bypassAllProbePort: []int{161, 137, 139, 135, 389, 443, 548, 1433, 6379, 1883, 5432, 1521, 3389, 3388, 3389, 33890, 33900},
		sslSecondProbeMap:  []string{"TCP_TerminalServerCookie", "TCP_TerminalServer"},
		allProbeMap:        []string{"TCP_GetRequest", "TCP_NULL"},
		sslProbeMap:        []string{"TCP_TLSSessionReq", "TCP_SSLSessionReq", "TCP_SSLv23SessionReq"},

		filter:  9,
		timeout: time.Second * 3,
	}

	// 预加载端口和探针的映射
	for i := 0; i <= 65535; i++ {
		nmap.portProbeMap[i] = []string{}
	}
	//加载探针相关信息
	nmap.loadProbes(nmapServiceProbes + nmapCustomizeProbes)

	// 新增探针，修复无法识别 HTTP 服务的问题
	pro := *nmap.probeNameMap["TCP_GetRequest"]
	pro.name = "TCP_GetRequest1.1"
	pro.sendRaw = "GET /test HTTP/1.1\r\n\r\n"
	nmap.probeNameMap["TCP_GetRequest1.1"] = &pro

	//修复fallback
	nmap.fixFallback()
	//自定义匹配规则
	nmap.customNmapMatch()
	//优化检测逻辑，及端口对应的默认探针
	nmap.optimizeNmapProbes()
	//排序，稀有度越高排序越靠前
	nmap.sslSecondProbeMap = nmap.sortOfRarity(nmap.sslSecondProbeMap)
	nmap.allProbeMap = nmap.sortOfRarity(nmap.allProbeMap)
	nmap.sslProbeMap = nmap.sortOfRarity(nmap.sslProbeMap)
	for port, probeList := range nmap.portProbeMap {
		nmap.portProbeMap[port] = nmap.sortOfRarity(probeList)
	}

	return nmap
}

// GuessService  猜测端口对应的服务类型
func (n *Nmap) GuessService(port int) string {
	if protocol, err := n.portService[port]; !err {
		return ""
	} else {
		return protocol
	}

}

// 添加匹配规则
func (n *Nmap) addMatch(probeName string, commandArgs string) {
	var probe = n.probeNameMap[probeName]
	probe.loadMatch(commandArgs, false)
}

// 加载 Nmap 需要使用的探针
func (n *Nmap) loadProbes(nmapProbes string) {
	lines := strings.Split(nmapProbes, "\n")
	var probeGroups [][]string
	var probeLines []string
	for _, line := range lines {
		//提取有效探针命令
		if !n.isCommand(line) {
			continue
		}
		commandName := line[:strings.Index(line, " ")]
		//暂时没有相应的命令
		if commandName == "Exclude" {
			n.loadExclude(line)
			continue
		}
		if commandName == "Probe" {
			if len(probeLines) != 0 {
				probeGroups = append(probeGroups, probeLines)
				probeLines = []string{}
			}
		}
		// 截止到下个 probe 出现之前，所有的数据都是该探针的数据
		probeLines = append(probeLines, line)
	}
	probeGroups = append(probeGroups, probeLines)

	for _, probeGroup := range probeGroups {
		probe := parseProbe(probeGroup)
		n.pushProbe(*probe)
	}
}

// 加载需要排除的命令
func (n *Nmap) loadExclude(expr string) {
	n.excludePort = portlist.ParsePortList(expr)
}

// 将探针绑定到 Nmap 实例上
func (n *Nmap) pushProbe(probe Probe) {
	//将所有探针全部绑定到 Nmap 实例，随后进行探针稀有度排序
	n.probeSort = append(n.probeSort, probe.name)
	n.probeNameMap[probe.name] = &probe

	//建立端口扫描对应表，将根据端口号决定使用何种请求包
	//如果端口列表为空，则为全端口
	//如果探针的稀有度大于我们的筛选稀有度，则不使用该探针
	if probe.rarity > n.filter {
		return
	}
	//现将所有探针都归到  0 端口
	n.portProbeMap[0] = append(n.portProbeMap[0], probe.name)

	//分别压入sslports,ports的端口下属的探针名称
	for _, i := range probe.ports {
		n.portProbeMap[i] = append(n.portProbeMap[i], probe.name)
	}

	for _, i := range probe.sslports {
		n.portProbeMap[i] = append(n.portProbeMap[i], probe.name)
	}
}

// 修复 fallback 备用策略
func (n *Nmap) fixFallback() {
	for probeName, probeType := range n.probeNameMap {
		fallback := probeType.fallback
		if fallback == "" {
			continue
		}
		// 如果存在 fallback 探针直接使用，否则使用 UDP
		if _, ok := n.probeNameMap["TCP_"+fallback]; ok {
			n.probeNameMap[probeName].fallback = "TCP_" + fallback
		} else {
			n.probeNameMap[probeName].fallback = "UDP_" + fallback
		}
	}
}

// 判断字符串是否为匹配命令
func (n *Nmap) isCommand(line string) bool {
	//删除注释行和空行
	if len(line) < 2 {
		return false
	}
	if line[:1] == "#" {
		return false
	}
	//删除异常命令
	commandName := line[:strings.Index(line, " ")]
	commandArr := []string{
		"Exclude", "Probe", "match", "softmatch", "ports", "sslports", "totalwaitms", "tcpwrappedms", "rarity", "fallback",
	}
	for _, item := range commandArr {
		if item == commandName {
			return true
		}
	}
	return false
}

// 自定义匹配规则
func (n *Nmap) customNmapMatch() {
	n.addMatch("TCP_GetRequest", `echo m|^GET / HTTP/1.0\r\n\r\n$|s`)
	n.addMatch("TCP_GetRequest", `mongodb m|.*It looks like you are trying to access MongoDB.*|s p/MongoDB/`)
	n.addMatch("TCP_GetRequest", `http m|^HTTP/1\.[01] \d\d\d (?:[^\r\n]+\r\n)*?Server: ([^\r\n]+)| p/$1/`)
	n.addMatch("TCP_GetRequest", `http m|^HTTP/1\.[01] \d\d\d|`)
	n.addMatch("TCP_GetRequest1.1", `echo m|^GET / HTTP/1.0\r\n\r\n$|s`)
	n.addMatch("TCP_GetRequest1.1", `mongodb m|.*It looks like you are trying to access MongoDB.*|s p/MongoDB/`)
	n.addMatch("TCP_GetRequest1.1", `http m|^HTTP/1\.[01] \d\d\d (?:[^\r\n]+\r\n)*?Server: ([^\r\n]+)| p/$1/`)
	n.addMatch("TCP_GetRequest1.1", `http m|^HTTP/1\.[01] \d\d\d|`)
	n.addMatch("TCP_NULL", `mysql m|.\x00\x00..j\x04Host '.*' is not allowed to connect to this MariaDB server| p/MariaDB/`)
	n.addMatch("TCP_NULL", `mysql m|.\x00\x00..j\x04Host '.*' is not allowed to connect to this MySQL server| p/MySQL/`)
	n.addMatch("TCP_NULL", `mysql m|.\x00\x00\x00\x0a(\d+\.\d+\.\d+)\x00.*caching_sha2_password\x00| p/MariaDB/ v/$1/`)
	n.addMatch("TCP_NULL", `mysql m|.\x00\x00\x00\x0a(\d+\.\d+\.\d+)\x00.*caching_sha2_password\x00| p/MariaDB/ v/$1/`)
	n.addMatch("TCP_NULL", `mysql m|.\x00\x00\x00\x0a([\d.-]+)-MariaDB\x00.*mysql_native_password\x00| p/MariaDB/ v/$1/`)
	n.addMatch("TCP_NULL", `redis m|-DENIED Redis is running in.*| p/Redis/ i/Protected mode/`)
	n.addMatch("TCP_NULL", `telnet m|^.*Welcome to visit (.*) series router!.*|s p/$1 Router/`)
	n.addMatch("TCP_NULL", `telnet m|^Username: ??|`)
	n.addMatch("TCP_NULL", `telnet m|^.*Telnet service is disabled or Your telnet session has expired due to inactivity.*|s i/Disabled/`)
	n.addMatch("TCP_NULL", `telnet m|^.*Telnet connection from (.*) refused.*|s i/Refused/`)
	n.addMatch("TCP_NULL", `telnet m|^.*Command line is locked now, please retry later.*\x0d\x0a\x0d\x0a|s i/Locked/`)
	n.addMatch("TCP_NULL", `telnet m|^.*Warning: Telnet is not a secure protocol, and it is recommended to use Stelnet.*|s`)
	n.addMatch("TCP_NULL", `telnet m|^telnetd:|s`)
	n.addMatch("TCP_NULL", `telnet m|^.*Quopin CLI for (.*)\x0d\x0a\x0d\x0a|s p/$1/`)
	n.addMatch("TCP_NULL", `telnet m|^\x0d\x0aHello, this is FRRouting \(version ([\d.]+)\).*|s p/FRRouting/ v/$1/`)
	n.addMatch("TCP_NULL", `telnet m|^.*User Access Verification.*Username:|s`)
	n.addMatch("TCP_NULL", `telnet m|^Connection failed.  Windows CE Telnet Service cannot accept anymore concurrent users.|s o/Windows/`)
	n.addMatch("TCP_NULL", `telnet m|^\x0d\x0a\x0d\x0aWelcome to the host.\x0d\x0a.*|s o/Windows/`)
	n.addMatch("TCP_NULL", `telnet m|^.*Welcome Visiting Huawei Home Gateway\x0d\x0aCopyright by Huawei Technologies Co., Ltd.*Login:|s p/Huawei/`)
	n.addMatch("TCP_NULL", `telnet m|^..\x01..\x03..\x18..\x1f|s p/Huawei/`)
	n.addMatch("TCP_NULL", `smtp m|^220 ([a-z0-1.-]+).*| h/$1/`)
	n.addMatch("TCP_NULL", `ftp m|^220 H3C Small-FTP Server Version ([\d.]+).* | p/H3C Small-FTP/ v/$1/`)
	n.addMatch("TCP_NULL", `ftp m|^421[- ]Service not available..*|`)
	n.addMatch("TCP_NULL", `ftp m|^220[- ].*filezilla.*|i p/FileZilla/`)
	n.addMatch("TCP_TerminalServerCookie", `ms-wbt-server m|^\x03\0\0\x13\x0e\xd0\0\0\x124\0\x02.*\0\x02\0\0\0| p/Microsoft Terminal Services/ o/Windows/ cpe:/o:microsoft:windows/a`)
	n.addMatch("TCP_redis-server", `redis m|^.*redis_version:([.\d]+)\n|s p/Redis key-value store/ v/$1/ cpe:/a:redislabs:redis:$1/`)
	n.addMatch("TCP_redis-server", `redis m|^-NOAUTH Authentication required.|s p/Redis key-value store/`)
}

// 优化 Nmap 探针
func (n *Nmap) optimizeNmapProbes() {
	n.probeNameMap["TCP_GenericLines"].sslports = n.probeNameMap["TCP_GenericLines"].sslports.Append(456, 993, 994, 995)
	//优化检测逻辑，及端口对应的默认探针
	n.portProbeMap[993] = append([]string{"TCP_GenericLines"}, n.portProbeMap[993]...)
	n.portProbeMap[994] = append([]string{"TCP_GenericLines"}, n.portProbeMap[994]...)
	n.portProbeMap[995] = append([]string{"TCP_GenericLines"}, n.portProbeMap[995]...)
	n.portProbeMap[465] = append([]string{"TCP_GenericLines"}, n.portProbeMap[465]...)
	n.portProbeMap[3390] = append(n.portProbeMap[3390], "TCP_TerminalServer")
	n.portProbeMap[3390] = append(n.portProbeMap[3390], "TCP_TerminalServerCookie")
	n.portProbeMap[33890] = append(n.portProbeMap[33890], "TCP_TerminalServer")
	n.portProbeMap[33890] = append(n.portProbeMap[33890], "TCP_TerminalServerCookie")
	n.portProbeMap[33900] = append(n.portProbeMap[33900], "TCP_TerminalServer")
	n.portProbeMap[33900] = append(n.portProbeMap[33900], "TCP_TerminalServerCookie")
	n.portProbeMap[7890] = append(n.portProbeMap[7890], "TCP_Socks5")
	n.portProbeMap[7891] = append(n.portProbeMap[7891], "TCP_Socks5")
	n.portProbeMap[4000] = append(n.portProbeMap[4000], "TCP_Socks5")
	n.portProbeMap[2022] = append(n.portProbeMap[2022], "TCP_Socks5")
	n.portProbeMap[6000] = append(n.portProbeMap[6000], "TCP_Socks5")
	n.portProbeMap[7000] = append(n.portProbeMap[7000], "TCP_Socks5")
	//将TCP_GetRequest的fallback参数设置为NULL探针，避免漏资产
	n.probeNameMap["TCP_GenericLines"].fallback = "TCP_NULL"
	n.probeNameMap["TCP_GetRequest"].fallback = "TCP_NULL"
	n.probeNameMap["TCP_GetRequest1.1"].fallback = "TCP_NULL"
	n.probeNameMap["TCP_TerminalServerCookie"].fallback = "TCP_GetRequest"
	n.probeNameMap["TCP_TerminalServer"].fallback = "TCP_GetRequest"
}

// sortOfRarity  在 Nmap 中，rarity 表示一个端口或服务的罕见程度或普及程度。
// 这个值越高，表示这个端口或服务出现得越少，越不常见。这个值是通过分析 Nmap 的扫描结果统计得出的。Nmap 可以根据这个值，对扫描结果进行排序，从而更快地发现那些罕见的、有可能是安全漏洞的服务和端口。
// 在 Nmap 的默认配置中，rarity 值小于 8 的端口被认为是“常见”的。
func (n *Nmap) sortOfRarity(probeList ProbeList) ProbeList {
	if len(probeList) == 0 {
		return probeList
	}
	var raritySplice []int
	for _, probeName := range probeList {
		rarity := n.probeNameMap[probeName].rarity
		raritySplice = append(raritySplice, rarity)
	}

	for i := 0; i < len(raritySplice)-1; i++ {
		for j := 0; j < len(raritySplice)-i-1; j++ {
			if raritySplice[j] > raritySplice[j+1] {
				m := raritySplice[j+1]
				raritySplice[j+1] = raritySplice[j]
				raritySplice[j] = m
				mp := probeList[j+1]
				probeList[j+1] = probeList[j]
				probeList[j] = mp
			}
		}
	}

	for _, probeName := range probeList {
		rarity := n.probeNameMap[probeName].rarity
		raritySplice = append(raritySplice, rarity)
	}

	return probeList
}

// ScanService  当扫描出开放端口后，再次扫描进行服务识别等操作
func (n *Nmap) ScanService(ip string, port int) (status result.Status, response *result.RecognizeResponse) {
	var probeNames ProbeList
	//如果端口为需要绕过的端口，则把默认的探针加载到该端口对应的探针列表中，反之则把该端口的探针加载到默认的全部探针列表中，保证使用的探针都是和该端口相关的
	if n.bypassAllProbePort.Exist(port) == true {
		probeNames = append(n.portProbeMap[port], n.allProbeMap...)
	} else {
		probeNames = append(n.allProbeMap, n.portProbeMap[port]...)
	}
	//加载 SSL 相关的探针
	probeNames = append(probeNames, n.sslProbeMap...)
	//探针去重
	probeNames = probeNames.removeDuplicate()

	firstProbe := probeNames[0]
	status, response = n.getRealResponse(ip, port, n.timeout, firstProbe)
	// 只有确定端口关闭或者成功识别出服务才会结束，其他情况继续使用其他探针进行服务识别
	if status == result.Closed || status == result.Matched {
		return status, response
	}
	otherProbes := probeNames[1:]
	return n.getRealResponse(ip, port, n.timeout, otherProbes...)
}

// 获取真实响应
func (n *Nmap) getRealResponse(host string, port int, timeout time.Duration, probes ...string) (status result.Status, response *result.RecognizeResponse) {
	status, response = n.getResponseByProbes(host, port, timeout, probes...)
	// 如果服务识别未成功，继续根据其他探针进行服务识别
	if status != result.Matched {
		return status, response
	}
	//如果通过指纹识别发现开放的有 SSL 服务，则开始使用 SSL 相关的探针去扫描
	if response.Fingerprint.Service == "ssl" {
		status, response = n.getResponseBySSLSecondProbes(host, port, timeout)
		if status == result.Matched {
			return result.Matched, response
		}
	}
	return status, response
}

// 通过探针获取响应
func (n *Nmap) getResponseByProbes(host string, port int, timeout time.Duration, probes ...string) (status result.Status, response *result.RecognizeResponse) {
	var responseNotMatch *result.RecognizeResponse
	for _, probeName := range probes {
		////不重复使用探针，仅适用于单个 IP+PORT 的扫描情况，一旦多 IP+多 PORT 会出现少使用探针的情况
		//if n.probeUsed.exist(probeName) {
		//	continue
		//}
		//n.probeUsed = append(n.probeUsed, probeName)
		probe := n.probeNameMap[probeName]
		status, response = n.getResponse(host, port, probe.sslports.Exist(port), timeout, probe)
		// 端口开放情况为关闭或者能识别到服务则直接结束
		if status == result.Closed || status == result.Matched {
			responseNotMatch = nil
			break
		}
		// 端口开放情况为未匹配到服务的，继续进行匹配
		if status == result.NotMatched {
			responseNotMatch = response
		}
	}
	if responseNotMatch != nil {
		response = responseNotMatch
	}
	return status, response
}

// 通过 SSL 探针二次获取响应
func (n *Nmap) getResponseBySSLSecondProbes(host string, port int, timeout time.Duration) (status result.Status, response *result.RecognizeResponse) {
	status, response = n.getResponseByProbes(host, port, timeout, n.sslSecondProbeMap...)
	// 如果服务识别失败或者探针自带的开放服务为 SSL，则继续探测，TLS 参数设置为 true
	if status != result.Matched || response.Fingerprint.Service == "ssl" {
		status, response = n.getResponseByHTTPS(host, port, timeout)
	}
	// 如果服务识别成功并且探针自带的开放服务不为 SSL
	if status == result.Matched && response.Fingerprint.Service != "ssl" {
		// 使用了 SSL 探针进行服务识别，并且成功的话如果探针的服务为 http 直接将探针的服务修改为 https
		if response.Fingerprint.Service == "http" {
			response.Fingerprint.Service = "https"
		}
		return result.Matched, response
	}
	return result.NotMatched, response
}

// 通过 HTTPS 获取响应
func (n *Nmap) getResponseByHTTPS(host string, port int, timeout time.Duration) (status result.Status, response *result.RecognizeResponse) {
	var httpRequest = n.probeNameMap["TCP_GetRequest"]
	return n.getResponse(host, port, true, timeout, httpRequest)
}

// 获取响应基础方法
func (n *Nmap) getResponse(host string, port int, tls bool, timeout time.Duration, probe *Probe) (result.Status, *result.RecognizeResponse) {
	//DNS 服务默认端口为 53，判定是否为 DNS 服务,如果没有使用 DNS，则默认端口不开放
	if port == 53 {
		if n.dnsScan(host, port) {
			return result.Matched, &result.RecognizeResponse{
				IP:   host,
				Port: port,
				//ResponseRaw: "DnsServer",
				TLS:      false,
				Protocol: "udp",
				Fingerprint: &fingerprint.Fingerprint{
					Service: "dns",
				}}
		} else {
			return result.Closed, nil
		}
	}
	text, tls, err := probe.scan(host, port, tls, timeout, 10240)
	if err != nil {
		// 如果是第一步连接的时候就出错，认为端口关闭
		if strings.Contains(err.Error(), "STEP1") {
			return result.Closed, nil
		}
		// 如果是第二步读取数据的时候出错，认为端口关闭
		if strings.Contains(err.Error(), "STEP2") {
			return result.Closed, nil
		}
		// 如果协议是 UDP 但是连接被拒绝，认为端口关闭
		if probe.protocol == "UDP" && strings.Contains(err.Error(), "refused") {
			return result.Closed, nil
		}
		// 如果不是上述情况，认为端口开放
		return result.Open, nil
	}

	response := &result.RecognizeResponse{
		IP:   host,
		Port: port,
		//ResponseRaw: strings.TrimSpace(text),
		TLS:         tls,
		Protocol:    probe.protocol,
		Fingerprint: &fingerprint.Fingerprint{},
	}

	//若存在返回包，则开始捕获指纹
	fingerPrint := n.getFinger(text, tls, probe.name)
	response.Fingerprint = fingerPrint

	if fingerPrint.Service == "" {
		return result.NotMatched, response
	} else {
		return result.Matched, response
	}
}

// DNS 扫描，判断是否为 DNS 服务
func (n *Nmap) dnsScan(host string, port int) bool {
	domainServer := fmt.Sprintf("%s:%d", host, port)
	client := dns.Client{
		Timeout: 2 * time.Second,
	}
	msg := dns.Msg{}
	// 最终都会指向一个ip 也就是typeA, 这样就可以返回所有层的cname.
	msg.SetQuestion("www.baidu.com.", dns.TypeA)
	_, _, err := client.Exchange(&msg, domainServer)
	if err != nil {
		return false
	}
	return true
}

// 根据响应数据开始指纹识别
func (n *Nmap) getFinger(responseRaw string, tls bool, probeName string) *fingerprint.Fingerprint {
	responseData := n.convResponse(responseRaw)
	probe := n.probeNameMap[probeName]

	Fingerprint := probe.matchRunner(responseData)

	if tls == true {
		if Fingerprint.Service == "http" {
			Fingerprint.Service = "https"
		}
	}

	if Fingerprint.Service != "" || n.probeNameMap[probeName].fallback == "" {
		//标记当前探针名称
		Fingerprint.ProbeName = probeName
		return Fingerprint
	}

	fallback := n.probeNameMap[probeName].fallback
	fallbackProbe := n.probeNameMap[fallback]
	for fallback != "" {
		Fingerprint = fallbackProbe.matchRunner(responseData)
		fallback = n.probeNameMap[fallback].fallback
		if Fingerprint.Service != "" {
			break
		}
	}
	//标记当前探针名称
	Fingerprint.ProbeName = probeName
	return Fingerprint
}

// 重置响应数据
func (n *Nmap) convResponse(responseRaw string) string {
	//为了适配go语言的正则，只能将二进制强行转换成UTF-8
	responseData := []byte(responseRaw)
	var tmpResult []rune
	for _, i := range responseData {
		tmpResult = append(tmpResult, rune(i))
	}
	return string(tmpResult)
}
