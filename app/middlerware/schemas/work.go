package schemas

type PortScanParams struct {
	IP       string `json:"ip" binding:"required"`
	Port     string `json:"port" binding:"required"`
	ScanType string `json:"scan_type"` // 扫描模式，CONNECT/SYC
	CDN      bool   `json:"cdn"`       // 是否排除 CDN
	WAF      bool   `json:"waf"`       // 是否排除 WAF
	Cloud    bool   `json:"cloud"`     // 是否排除 Cloud
}
