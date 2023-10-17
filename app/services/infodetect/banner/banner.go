package banner

import (
	"fmt"
	osutil "github.com/projectdiscovery/utils/os"
	"gitlab.example.com/zhangweijie/portscan/global"
	"gitlab.example.com/zhangweijie/portscan/services/pportscan/privileges"
	"gitlab.example.com/zhangweijie/tool-sdk/middleware/logger"
)

// ShowNetworkCapabilities 显示网络功能扫描类型可能与正在运行的用户
func ShowNetworkCapabilities(ScanType string) string {
	var accessLevel, scanType string

	switch {
	case privileges.IsPrivileged && ScanType == global.SynScan:
		accessLevel = "root"
		if osutil.IsLinux() {
			accessLevel = "CAP_NET_RAW"
		}
		scanType = "SYN"
	default:
		accessLevel = "non root"
		scanType = "CONNECT"
	}
	logger.Info(fmt.Sprintf("Running %s scan with %s privileges\n", scanType, accessLevel))

	return scanType
}
