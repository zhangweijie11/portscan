package result

import (
	"gitlab.example.com/zhangweijie/portscan/services/service_recognize/fingerprint"
	"sync"
)

const (
	Closed     Status = 0x000a1
	Open              = 0x000b2
	Matched           = 0x000c3
	NotMatched        = 0x000d4
	Unknown           = 0x000e5
)

type Status int

func (s Status) String() string {
	switch s {
	case Closed:
		return "Closed"
	case Open:
		return "Open"
	case Matched:
		return "Matched"
	case NotMatched:
		return "NotMatched"
	case Unknown:
		return "Unknown"
	default:
		return "Unknown"
	}
}

// RecognizeResult 服务识别结果
type RecognizeResult struct {
	sync.RWMutex
	RecognizeResponses map[string]map[int]*RecognizeResponse
}

type RecognizeResponse struct {
	IP          string                   `json:"ip"`
	Port        int                      `json:"port"`
	Status      string                   `json:"status"`
	TLS         bool                     `json:"tls"`
	Protocol    string                   `json:"protocol"`
	Fingerprint *fingerprint.Fingerprint `json:"fingerprint"`
	//ResponseRaw string                   `json:"responseRaw"`
}

// AddRecognizeResponse  添加具体的响应数据
func (rr *RecognizeResult) AddRecognizeResponse(ip string, port int, response *RecognizeResponse) {
	rr.Lock()
	defer rr.Unlock()

	if _, ok := rr.RecognizeResponses[ip]; !ok {
		rr.RecognizeResponses[ip] = make(map[int]*RecognizeResponse)
	}

	rr.RecognizeResponses[ip][port] = response

}

// NewRecognizeResult 初始化结果结构体
func NewRecognizeResult() *RecognizeResult {
	return &RecognizeResult{
		RecognizeResponses: make(map[string]map[int]*RecognizeResponse),
	}
}

// NewResponse 初始化响应数据结构体
func NewResponse(ip string, port int, status Status) *RecognizeResponse {
	return &RecognizeResponse{IP: ip, Port: port, Status: status.String(), Fingerprint: &fingerprint.Fingerprint{}}
}
