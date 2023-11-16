package result

import (
	"gitlab.example.com/zhangweijie/portscan/services/service_recognize/result"
)

type WorkerDetectResult struct {
	ServiceRecognizeResult map[string]map[int]*result.Response // 服务识别结果
	IpType                 map[string]string                   // IP 的类型
}

type InfoDetectResult struct {
	Ip         string             `json:"ip"`
	IpType     string             `json:"ipType"`
	PortResult []*result.Response `json:"portResult"`
}

func NewWorkerDetectResult() *WorkerDetectResult {
	return &WorkerDetectResult{
		ServiceRecognizeResult: make(map[string]map[int]*result.Response),
		IpType:                 make(map[string]string),
	}
}

// AddRecognizeResult 验证当前结果中是否存在该 IP 和端口的服务识别结果
func (dr *WorkerDetectResult) AddRecognizeResult(ip string, port int, response *result.Response) {
	ipPorts, hasPorts := dr.ServiceRecognizeResult[ip]

	if !hasPorts {
		dr.ServiceRecognizeResult[ip] = map[int]*result.Response{
			port: response,
		}
	} else {
		ipPorts[port] = response
	}
}
