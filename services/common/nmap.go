package common

import (
	servicenmap "gitlab.example.com/zhangweijie/portscan/services/service_recognize/nmap"
)

var CustomerNmap *servicenmap.Nmap

func init() {
	CustomerNmap = servicenmap.NewNmap()
}
