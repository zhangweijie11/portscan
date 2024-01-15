package banner

import (
	"fmt"
	osutil "github.com/projectdiscovery/utils/os"
	"gitlab.example.com/zhangweijie/portscan/global"
	"gitlab.example.com/zhangweijie/portscan/middlerware/schemas"
	"gitlab.example.com/zhangweijie/portscan/services/pportscan/privileges"
	"gitlab.example.com/zhangweijie/tool-sdk/middleware/logger"
)

// ShowNetworkCapabilities 显示网络功能扫描类型可能与正在运行的用户
func ShowNetworkCapabilities(validParams interface{}) string {
	switch validParams.(type) {
	case *schemas.PortScanParams:
		validParam := validParams.(*schemas.PortScanParams)
		var accessLevel, scanType string

		switch {
		case privileges.IsOSSupported && privileges.IsPrivileged && validParam.ScanType == global.SynScan:
			accessLevel = "root"
			if osutil.IsLinux() {
				accessLevel = "CAP_NET_RAW"
			}
			scanType = "SYN"
		default:
			accessLevel = "non root"
			scanType = "CONNECT"
		}

		if validParam.HostDiscover.OnlyHostDiscover {
			logger.Info(fmt.Sprintf("Running Host Discover with %s privileges", accessLevel))
		}

		logger.Info(fmt.Sprintf("Running %s scan with %s privileges", scanType, accessLevel))

		return scanType
	case *schemas.HostDiscoverParams:
		validParam := validParams.(*schemas.HostDiscoverParams)
		var accessLevel, scanType string

		switch {
		case privileges.IsOSSupported && privileges.IsPrivileged && validParam.ScanType == global.SynScan:
			accessLevel = "root"
			if osutil.IsLinux() {
				accessLevel = "CAP_NET_RAW"
			}
			scanType = "SYN"
		default:
			accessLevel = "non root"
			scanType = "CONNECT"
		}

		if validParam.HostDiscover.OnlyHostDiscover {
			logger.Info(fmt.Sprintf("Running Host Discover with %s privileges", accessLevel))
		}

		logger.Info(fmt.Sprintf("Running %s scan with %s privileges", scanType, accessLevel))

		return scanType
	}

	return "CONNECT"
}
