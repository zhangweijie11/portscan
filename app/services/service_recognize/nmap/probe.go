package nmap

import (
	"fmt"
	"gitlab.example.com/zhangweijie/portscan/services/service_recognize/fingerprint"
	"gitlab.example.com/zhangweijie/portscan/services/service_recognize/portlist"
	"gitlab.example.com/zhangweijie/tool-sdk/middleware/logger"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Probe struct {
	//探针稀有度
	//rarity（稀有度）是一种衡量探测方式或探测脚本的使用频率的指标。通常情况下，探测方式或探测脚本的稀有度越高，使用它们进行探测时发现的问题和漏洞可能就越多。
	//在探针中，rarity 常常被用作探测策略中的权重参数，以决定探测方式在探测时的优先级和概率。
	//具体来说，当探针尝试使用多种探测方式进行探测时，它通常会根据这些方式的稀有度和可靠性等因素来计算它们在探测策略中的权重，以决定使用哪种探测方式进行探测。
	rarity int
	//探针名称
	name string
	//探针适用默认端口号
	ports portlist.PortList
	//探针适用SSL端口号
	sslports portlist.PortList

	totalwaitms  time.Duration
	tcpwrappedms time.Duration

	//探针对应指纹库
	matchGroup []*Matcher
	//探针指纹库若匹配失败，则会尝试使用fallback指定探针的指纹库
	fallback string

	//探针发送协议类型
	protocol string
	//探针发送数据
	sendRaw string
}

// 提取 UDP 和 TCP 协议探针
var probeExprRegx = regexp.MustCompile("^(UDP|TCP) ([a-zA-Z0-9-_./]+) (?:q\\|([^|]*)\\|)$")
var probeIntRegx = regexp.MustCompile(`^(\d+)$`)
var probeStrRegx = regexp.MustCompile(`^([a-zA-Z0-9-_./]+)$`)

// parseProbe  解析探针,会将探针的所有属性补充完整，一个探针会有多个匹配规则，
// 会集成到matchGroup匹配规则库，然后解析规则，补充规则的相关属性（包括规则对应的指纹信息）
func parseProbe(probeLines []string) *Probe {
	var probe = &Probe{}
	probe.ports = portlist.EmptyPortList
	probe.sslports = portlist.EmptyPortList
	for _, probeLine := range probeLines {
		probe.loadLine(probeLine)
	}
	return probe
}

// loadLine  为探针加载具体的每条命令
func (p *Probe) loadLine(probeLine string) {
	//分解命令
	index := strings.Index(probeLine, " ")
	commandName := probeLine[:index]
	commandArgs := probeLine[index+1:]

	//逐行处理
	switch commandName {
	case "Probe":
		p.loadProbe(commandArgs)
	case "match":
		p.loadMatch(commandArgs, false)
	case "softmatch":
		p.loadMatch(commandArgs, true)
	case "ports":
		p.loadPorts(commandArgs, false)
	case "sslports":
		p.loadPorts(commandArgs, true)
	case "totalwaitms":
		p.totalwaitms = time.Duration(p.getInt(commandArgs)) * time.Millisecond
	case "tcpwrappedms":
		p.tcpwrappedms = time.Duration(p.getInt(commandArgs)) * time.Millisecond
	case "rarity":
		p.rarity = p.getInt(commandArgs)
	case "fallback":
		p.fallback = p.getString(commandArgs)
	}
}

// loadProbe  加载探针
func (p *Probe) loadProbe(commandArgs string) {
	//Probe <protocol> <probename> <probestring>
	//eg.    Probe TCP teamtalk-login q|login\n|
	if !probeExprRegx.MatchString(commandArgs) {
		logger.Warn("probe 语句格式不正确")
	}

	//eg.  [TCP teamtalk-login q|login\n| TCP teamtalk-login login\n]
	args := probeExprRegx.FindStringSubmatch(commandArgs)
	if args[1] == "" || args[2] == "" {
		logger.Warn("probe 参数格式不正确")
	}
	p.protocol = args[1]
	p.name = args[1] + "_" + args[2]
	str := args[3]
	str = strings.ReplaceAll(str, `\0`, `\x00`)
	str = strings.ReplaceAll(str, `"`, `${double-quoted}`)
	str = `"` + str + `"`
	str, _ = strconv.Unquote(str)
	str = strings.ReplaceAll(str, `${double-quoted}`, `"`)
	p.sendRaw = str
}

// loadMatch  加载匹配规则
func (p *Probe) loadMatch(commandArgs string, soft bool) {
	//"match": misc.MakeRegexpCompile("^([a-zA-Z0-9-_./]+) m\\|([^|]+)\\|([is]{0,2}) (.*)$"),
	//match <Service> <pattern>|<patternopt> [<versioninfo>]
	//	"matchVersioninfoProductname": misc.MakeRegexpCompile("p/([^/]+)/"),
	//	"matchVersioninfoVersion":     misc.MakeRegexpCompile("v/([^/]+)/"),
	//	"matchVersioninfoInfo":        misc.MakeRegexpCompile("i/([^/]+)/"),
	//	"matchVersioninfoHostname":    misc.MakeRegexpCompile("h/([^/]+)/"),
	//	"matchVersioninfoOS":          misc.MakeRegexpCompile("o/([^/]+)/"),
	//	"matchVersioninfoDevice":      misc.MakeRegexpCompile("d/([^/]+)/"),

	match := parseMatch(commandArgs, soft)

	p.matchGroup = append(p.matchGroup, match)
}

// loadPorts  加载探针对应端口
func (p *Probe) loadPorts(commandArgs string, ssl bool) {
	if ssl {
		//将探针适用的 SSL 端口绑定到探针上
		p.sslports = portlist.ParsePortList(commandArgs)
	} else {
		//将探针适用的非 SSL 端口绑定到探针上
		p.ports = portlist.ParsePortList(commandArgs)
	}
}

// getInt  获取探针稀有度（探针优先级别）
func (p *Probe) getInt(commandArgs string) int {
	if !probeIntRegx.MatchString(commandArgs) {
		logger.Warn("totalwaitms or tcpwrappedms 语句参数不正确")
	}
	i, _ := strconv.Atoi(probeIntRegx.FindStringSubmatch(commandArgs)[1])
	return i
}

// getString  获取探针备用策略
func (p *Probe) getString(commandArgs string) string {
	if !probeStrRegx.MatchString(commandArgs) {
		logger.Warn("fallback 语句参数不正确")
	}
	return probeStrRegx.FindStringSubmatch(commandArgs)[1]
}

// scan  适应探针根据不同协议开启扫描
func (p *Probe) scan(host string, port int, tls bool, timeout time.Duration, size int) (string, bool, error) {
	uri := net.JoinHostPort(host, fmt.Sprint(port))

	//根据实际 IP，Port替换探针发送的的数据包
	sendRaw := strings.Replace(p.sendRaw, "{Host}", fmt.Sprintf("%s:%d", host, port), -1)

	// 能请求到数据，text 就不为空
	text, err := Send(p.protocol, tls, uri, sendRaw, timeout, size)
	if err == nil {
		return text, tls, nil
	}
	//如果是 TLS 协议在第一步连接失败，使用 TCP 协议重新尝试
	if strings.Contains(err.Error(), "STEP1") && tls == true {
		text, err = Send(p.protocol, false, uri, p.sendRaw, timeout, size)
		return text, false, err
	}
	return text, tls, err
}

// matchRunner  开始规则匹配
func (p *Probe) matchRunner(responseData string) *fingerprint.Fingerprint {
	var fingerPrint = &fingerprint.Fingerprint{}
	var softFilter string

	for _, match := range p.matchGroup {
		//实现软筛选
		if softFilter != "" {
			if match.service != softFilter {
				continue
			}
		}

		if match.patternRegexp.MatchString(responseData) {
			//标记当前正则
			fingerPrint.MatchRegexString = match.patternRegexp.String()
			if match.soft {
				//如果为软捕获，这设置筛选器
				fingerPrint.Service = match.service
				softFilter = match.service
				continue
			} else {
				//如果为硬捕获则直接获取指纹信息
				match.makeVersionInfo(responseData, fingerPrint)
				fingerPrint.Service = match.service
				return fingerPrint
			}
		}
	}
	return fingerPrint
}
