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
	scanner := sc.NewScanner(cdn, waf, cloud, scanType)
	scanner.Ports = validPorts
	err := scanner.SplitAndParseIP(validIps)
	if err != nil {
		logger.Warn("ipranger 出现问题")
	}
	defer scanner.Close()
	if privileges.IsPrivileged && scanType == global.SynScan {
		err = scanner.SetupHandlers()
		if err != nil {
			logger.Warn("ipranger 出现问题")
		}
		scanner.StartWorkers()
	}

	ipsCallback := scanner.GetPreprocessedIps
	// 将 IP 缩小到最少的 CIDR 量
	ipStatus, targets, targetsV4, targetsV6, _ := scanner.GetTargetIps(ipsCallback)
	if err != nil {
		return finalResult
	}
	var targetsCount, portsCount uint64
	for _, target := range append(targetsV4, targetsV6...) {
		if target == nil {
			continue
		}
		targetsCount += mapcidr.AddressCountIpnet(target)
	}
	portsCount = uint64(len(scanner.Ports))
	Range := targetsCount * portsCount

	currentSeed := time.Now().UnixNano()
	b := blackrock.New(int64(Range), currentSeed)
	// 由于网络不可靠性，无论以前的扫描结果如何，都会执行重试
	for currentRetry := 0; currentRetry < scanner.Retries; currentRetry++ {
		for index := int64(0); index < int64(Range); index++ {
			xxx := b.Shuffle(index)
			ipIndex := xxx / int64(portsCount)
			portIndex := int(xxx % int64(portsCount))
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
				if scanner.ScanType == global.ConnectScan {
					scanner.WgScan.Add()
					go scanner.ScanOpenPort(ip, port)
				} else {
					scanner.RawSocketEnumeration(ip, port)
				}

			}

		}
	}

	time.Sleep(time.Second * 3)

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
