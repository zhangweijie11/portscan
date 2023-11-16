package result

import (
	"gitlab.example.com/zhangweijie/portscan/services/pportscan/portlist"
	"sync"

	"golang.org/x/exp/maps"
)

type HostResult struct {
	Host  string
	IP    string
	Ports []*portlist.Port
}

// PortScanResult 端口扫描结果
type PortScanResult struct {
	sync.RWMutex
	ipPorts map[string]map[string]*portlist.Port
	ips     map[string]struct{}
	skipped map[string]struct{}
}

// NewPortScanResult structure
func NewPortScanResult() *PortScanResult {
	ipPorts := make(map[string]map[string]*portlist.Port)
	ips := make(map[string]struct{})
	skipped := make(map[string]struct{})
	return &PortScanResult{ipPorts: ipPorts, ips: ips, skipped: skipped}
}

// GetIPs 获取 IP 数据
func (pr *PortScanResult) GetIPs() chan string {
	pr.Lock()

	out := make(chan string)

	go func() {
		defer close(out)
		defer pr.Unlock()

		for ip := range pr.ips {
			out <- ip
		}
	}()

	return out
}

func (pr *PortScanResult) HasIPS() bool {
	pr.RLock()
	defer pr.RUnlock()

	return len(pr.ips) > 0
}

// GetIpsPorts 获取 IP 和端口
func (pr *PortScanResult) GetIpsPorts() chan *HostResult {
	pr.RLock()

	out := make(chan *HostResult)

	go func() {
		defer close(out)
		defer pr.RUnlock()

		for ip, ports := range pr.ipPorts {
			if pr.HasSkipped(ip) {
				continue
			}
			out <- &HostResult{IP: ip, Ports: maps.Values(ports)}
		}
	}()

	return out
}

func (pr *PortScanResult) HasIPsPorts() bool {
	pr.RLock()
	defer pr.RUnlock()

	return len(pr.ipPorts) > 0
}

// AddPort to a specific ip
func (pr *PortScanResult) AddPort(ip string, p *portlist.Port) {
	pr.Lock()
	defer pr.Unlock()

	if _, ok := pr.ipPorts[ip]; !ok {
		pr.ipPorts[ip] = make(map[string]*portlist.Port)
	}

	pr.ipPorts[ip][p.String()] = p
	pr.ips[ip] = struct{}{}
}

// SetPorts for a specific ip
func (pr *PortScanResult) SetPorts(ip string, ports []*portlist.Port) {
	pr.Lock()
	defer pr.Unlock()

	if _, ok := pr.ipPorts[ip]; !ok {
		pr.ipPorts[ip] = make(map[string]*portlist.Port)
	}

	for _, p := range ports {
		pr.ipPorts[ip][p.String()] = p
	}
	pr.ips[ip] = struct{}{}
}

// IPHasPort 检查 IP 是否具有特定端口
func (pr *PortScanResult) IPHasPort(ip string, p *portlist.Port) bool {
	pr.RLock()
	defer pr.RUnlock()

	ipPorts, hasports := pr.ipPorts[ip]
	if !hasports {
		return false
	}
	_, hasport := ipPorts[p.String()]

	return hasport
}

// AddIp 结果添加 IP
func (pr *PortScanResult) AddIp(ip string) {
	pr.Lock()
	defer pr.Unlock()

	pr.ips[ip] = struct{}{}
}

// HasIP 检查是否存在 IP
func (pr *PortScanResult) HasIP(ip string) bool {
	pr.RLock()
	defer pr.RUnlock()

	_, ok := pr.ips[ip]
	return ok
}

func (pr *PortScanResult) IsEmpty() bool {
	return pr.Len() == 0
}

func (pr *PortScanResult) Len() int {
	pr.RLock()
	defer pr.RUnlock()

	return len(pr.ips)
}

// GetPortCount 返回该 IP 发现的端口数
func (pr *PortScanResult) GetPortCount(host string) int {
	pr.RLock()
	defer pr.RUnlock()

	return len(pr.ipPorts[host])
}

// AddSkipped 将 IP 添加到跳过的列表
func (pr *PortScanResult) AddSkipped(ip string) {
	pr.Lock()
	defer pr.Unlock()

	pr.skipped[ip] = struct{}{}
}

// HasSkipped 检查是否是需要跳过的 IP
func (pr *PortScanResult) HasSkipped(ip string) bool {
	pr.RLock()
	defer pr.RUnlock()

	_, ok := pr.skipped[ip]
	return ok
}
