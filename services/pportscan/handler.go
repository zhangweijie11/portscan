package pportscan

import (
	"context"
	"github.com/projectdiscovery/blackrock"
	"github.com/projectdiscovery/mapcidr"
	"gitlab.example.com/zhangweijie/portscan/global"
	"gitlab.example.com/zhangweijie/portscan/services/pportscan/portlist"
	"gitlab.example.com/zhangweijie/portscan/services/pportscan/privileges"
	"gitlab.example.com/zhangweijie/portscan/services/pportscan/result"
	sc "gitlab.example.com/zhangweijie/portscan/services/pportscan/scanner"
	"gitlab.example.com/zhangweijie/tool-sdk/middleware/logger"
	"time"
)

type FinalResult struct {
	IpPorts          map[string][]int
	PortScanIpStatus map[string]string
}

func NewFinalResult() FinalResult {
	return FinalResult{
		IpPorts:          make(map[string][]int),
		PortScanIpStatus: make(map[string]string),
	}
}

// GetOpenPort 获取开放端口
func GetOpenPort(ctx context.Context, validIps []string, validPorts []*portlist.Port, cdn, waf, cloud bool, scanType string) FinalResult {
	finalResult := NewFinalResult()
	scanner := sc.NewScanner(ctx, cdn, waf, cloud, scanType)
	defer scanner.Close()

	// 如果是半连接扫描，需要设置处理器
	if privileges.IsPrivileged && scanType == global.SynScan {
		err := scanner.SetupHandlers()
		if err != nil {
			logger.Warn("设置PCAP处理器出现问题")
			return finalResult
		}
		scanner.StartWorkers()
	}

	scanner.Ports = validPorts
	err := scanner.SplitAndParseIP(validIps)
	if err != nil {
		logger.Warn("创建 IPRanger 出现问题")
	}

	// 设置扫描器状态为初始化
	scanner.Phase.Set(sc.Init)

	ipsCallback := scanner.GetPreprocessedIps
	// 将 IP 缩小到最少的 CIDR 量
	ipStatus, targets, targetsV4, targetsV6, _ := scanner.GetTargetIps(ipsCallback)
	if err != nil {
		return finalResult
	}

	// 获取目标 IP 数量和端口数量
	var targetsCount, portsCount uint64
	for _, target := range append(targetsV4, targetsV6...) {
		if target == nil {
			continue
		}
		targetsCount += mapcidr.AddressCountIpnet(target)
	}
	portsCount = uint64(len(scanner.Ports))
	// 获取循环的数量
	Range := targetsCount * portsCount

	// 设置扫描器的状态为扫描
	scanner.Phase.Set(sc.Scan)

	// 由于网络不可靠性，无论以前的扫描结果如何，都会执行重试
	for currentRetry := 0; currentRetry < scanner.Retries; currentRetry++ {
		// 生成一个新的随机种子
		currentSeed := time.Now().UnixNano()
		// 使用 blackrock 包创建一个新的伪随机数生成器
		b := blackrock.New(int64(Range), currentSeed)
		for index := int64(0); index < int64(Range); index++ {
			// 通过随机数生成器生成一个随机数，用于乱序
			xxx := b.Shuffle(index)
			// 将随机数映射到 IP 和端口
			ipIndex := xxx / int64(portsCount)
			portIndex := int(xxx % int64(portsCount))
			// 根据生成的索引选择目标 IP 和端口
			ip := scanner.PickIP(targets, ipIndex)
			port := scanner.PickPort(portIndex)
			scanner.Limiter.Take()
			if scanner.ScanResults.HasSkipped(ip) {
				continue
			}
			select {
			case <-ctx.Done():
				return finalResult
			default:
				// 必须是 Linux 系统或者 Mac 系统的 ROOT 权限用户才能进行 SYN 扫描
				if privileges.IsOSSupported && privileges.IsPrivileged && scanner.ScanType == global.SynScan {
					scanner.RawSocketEnumeration(ip, port)
				} else {
					scanner.WgScan.Add()
					go scanner.ScanOpenPort(ip, port)
				}
			}
		}
		scanner.WgScan.Wait()
	}

	time.Sleep(time.Second * 3)
	scanner.Phase.Set(sc.Done)

	var ipsPorts []*result.HostResult
	for hostResult := range scanner.ScanResults.GetIpsPorts() {
		ipsPorts = append(ipsPorts, hostResult)
	}

	for _, ipsPort := range ipsPorts {
		ipStatus[ipsPort.IP] = "other"
		if _, ok := finalResult.IpPorts[ipsPort.IP]; !ok {
			finalResult.IpPorts[ipsPort.IP] = []int{}
		}
		for _, port := range ipsPort.Ports {
			finalResult.IpPorts[ipsPort.IP] = append(finalResult.IpPorts[ipsPort.IP], port.Port)
		}
	}

	finalResult.PortScanIpStatus = ipStatus

	return finalResult
}
