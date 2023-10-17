package utils

import (
	"fmt"
	"gitlab.example.com/zhangweijie/portscan/global"
	"gitlab.example.com/zhangweijie/portscan/services/pportscan/portlist"
	"gitlab.example.com/zhangweijie/portscan/services/pportscan/protocol"
	"net"
	"strconv"
	"strings"
)

// SplitAndParsePort  解析端口
func SplitAndParsePort(targetPorts string) ([]*portlist.Port, error) {
	// 检查字符串是否为空
	if targetPorts == "" {
		return nil, fmt.Errorf("无效的 PORT 列表: %s ", targetPorts)
	}

	var tmpPorts []*portlist.Port
	var stringPorts []string
	for _, targetPort := range strings.Split(targetPorts, ",") {
		switch strings.TrimSpace(strings.ToLower(targetPort)) {
		case "full":
			targetPort = global.Full
		case "top 1000":
			targetPort = global.NmapTop1000
		case "top 100":
			targetPort = global.NmapTop100
		}
		stringPorts = append(stringPorts, targetPort)
	}

	// 解析逗号分隔的端口范围
	oldPorts := strings.Split(strings.Join(stringPorts, ","), ",")

	// 遍历每个端口范围
	for _, oldPort := range oldPorts {
		portProtocol := protocol.TCP
		if strings.HasPrefix(oldPort, "u:") {
			portProtocol = protocol.UDP
			oldPort = strings.TrimPrefix(oldPort, "u:")
		}

		// 检查是否存在连字符
		if strings.Contains(oldPort, "-") {
			// 解析连字符分隔的起始端口和结束端口
			portParts := strings.Split(oldPort, "-")
			if len(portParts) != 2 {
				return nil, fmt.Errorf("无效的端口列表: %s ", oldPort)
			}

			startPort, err := strconv.Atoi(portParts[0])
			if err != nil {
				return nil, fmt.Errorf("无效的端口列表: %s ", portParts[0])
			}

			endPort, err := strconv.Atoi(portParts[1])
			if err != nil {
				return nil, fmt.Errorf("无效的端口列表: %s ", portParts[1])
			}

			if startPort > endPort || endPort > 65535 || startPort > 65535 {
				return nil, fmt.Errorf("无效的端口列表: %s ", oldPort)
			}

			// 将起始端口到结束端口之间的所有端口添加到结果中
			for i := startPort; i <= endPort; i++ {
				resultPort := &portlist.Port{
					Port:     i,
					Protocol: portProtocol,
				}
				tmpPorts = append(tmpPorts, resultPort)
			}

		} else {
			// 没有连字符，直接添加端口到结果中
			validPort, err := strconv.Atoi(oldPort)
			if err != nil || validPort > 65535 || validPort < 0 {
				return nil, fmt.Errorf("无效的端口列表: %s ", oldPort)
			}
			resultPort := &portlist.Port{
				Port:     validPort,
				Protocol: portProtocol,
			}
			tmpPorts = append(tmpPorts, resultPort)
		}
	}

	// 去重
	// 创建一个空的 map
	seen := make(map[string]struct{})

	// 创建一个新的切片
	var resultPorts []*portlist.Port

	// 遍历原始切片
	for _, tmpPort := range tmpPorts {
		// 如果元素在 map 中不存在，则将其存储在 map 中，并追加到新切片中
		if _, ok := seen[tmpPort.String()]; !ok {
			seen[tmpPort.String()] = struct{}{}
			resultPorts = append(resultPorts, tmpPort)
		}
	}

	return resultPorts, nil
}

// SplitAndParseIP  切割解析 IP
func SplitAndParseIP(targetIp string) ([]string, error) {
	// 检查字符串是否为空
	if targetIp == "" {
		return nil, fmt.Errorf("无效的 IP 列表: %s", targetIp)
	}

	var ips []string

	// 以逗号分隔IP地址
	ipList := strings.Split(targetIp, ",")
	for _, oldIp := range ipList {
		// CIDR格式，例如：1.1.1.1/24
		if strings.Contains(oldIp, "/") {
			_, ipNet, err := net.ParseCIDR(oldIp)
			if err == nil {
				// 获取IP范围内的所有IP地址
				for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
					if parsedIP := net.ParseIP(ip.String()); parsedIP != nil {
						ips = append(ips, parsedIP.String())
					}
				}
			} else {
				return nil, fmt.Errorf("无效的 IP 列表: %s", oldIp)
			}
		} else if strings.Contains(oldIp, "-") {
			// 范围格式，例如：1.1.1.1-5
			ipParts := strings.Split(oldIp, ".")
			startIP := ipParts[0] + "." + ipParts[1] + "." + ipParts[2] + "."

			start, err := strconv.Atoi(ipParts[3][:strings.Index(ipParts[3], "-")])
			if err != nil {
				return nil, fmt.Errorf("无效的 IP 列表: %s", oldIp)
			}
			end, err := strconv.Atoi(ipParts[3][strings.Index(ipParts[3], "-")+1:])
			if err != nil {
				return nil, fmt.Errorf("无效的 IP 列表: %s", oldIp)
			}

			for i := start; i <= end; i++ {
				parsedIP := net.ParseIP(startIP + strconv.Itoa(i))
				if parsedIP != nil {
					ips = append(ips, parsedIP.String())
				} else {
					return nil, fmt.Errorf("无效的 IP 列表: %s", oldIp)
				}
			}
		} else {
			// 单个IP地址
			parsedIP := net.ParseIP(oldIp)
			if parsedIP != nil {
				ips = append(ips, parsedIP.String())
			} else {
				return nil, fmt.Errorf("无效的 IP 列表: %s", oldIp)
			}
		}
	}

	// 去重
	// 创建一个空的 map
	seen := make(map[string]struct{})

	// 创建一个新的切片
	var result []string

	// 遍历原始切片
	for _, ip := range ips {
		// 如果元素在 map 中不存在，则将其存储在 map 中，并追加到新切片中
		if _, exists := seen[ip]; !exists {
			seen[ip] = struct{}{}
			result = append(result, ip)
		}
	}

	return result, nil
}

// inc  增加IP地址
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
