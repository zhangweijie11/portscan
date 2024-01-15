package schemas

type PortScanParams struct {
	IP           string       `json:"ip" binding:"required"`
	Port         string       `json:"port" binding:"required"`
	ScanType     string       `json:"scan_type"`     // 扫描模式，CONNECT/SYC
	CDN          bool         `json:"cdn"`           // 是否排除 CDN
	WAF          bool         `json:"waf"`           // 是否排除 WAF
	Cloud        bool         `json:"cloud"`         // 是否排除 Cloud
	HostDiscover HostDiscover `json:"host_discover"` // 主机发现参数
}

type HostDiscoverParams struct {
	IP           string       `json:"ip" binding:"required"`
	ScanType     string       `json:"scan_type"`     // 扫描模式，CONNECT/SYC
	CDN          bool         `json:"cdn"`           // 是否排除 CDN
	WAF          bool         `json:"waf"`           // 是否排除 WAF
	Cloud        bool         `json:"cloud"`         // 是否排除 Cloud
	HostDiscover HostDiscover `json:"host_discover"` // 主机发现参数
}

type HostDiscover struct {
	OnlyHostDiscover  bool     `json:"only_host_discover"`  // 是否只进行主机发现
	SkipHostDiscovery bool     `json:"skip_host_discovery"` // 是否跳过主机发现
	TcpSynPingProbes  []string `json:"tcp_syn_ping_probes"`
	TcpAckPingProbes  []string `json:"tcp_ack_ping_probes"`
	// UdpPingProbes               goflags.StringSlice - planned
	// STcpInitPingProbes          goflags.StringSlice - planned
	IcmpEchoRequestProbe        bool `json:"icmp_echo_request_probe"`
	IcmpTimestampRequestProbe   bool `json:"icmp_timestamp_request_probe"`
	IcmpAddressMaskRequestProbe bool `json:"icmp_address_mask_request_probe"`
	// IpProtocolPingProbes        goflags.StringSlice - planned
	ArpPing                   bool `json:"arp_ping"`
	IPv6NeighborDiscoveryPing bool `json:"ipv6_neighbor_discovery_ping"`
}
