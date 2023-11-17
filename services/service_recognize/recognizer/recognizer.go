package recognizer

import (
	"context"
	"fmt"
	"github.com/projectdiscovery/ratelimit"
	"github.com/remeh/sizedwaitgroup"
	"gitlab.example.com/zhangweijie/portscan/global"
	"gitlab.example.com/zhangweijie/portscan/services/service_recognize/nmap"
	"gitlab.example.com/zhangweijie/portscan/services/service_recognize/result"
	"gitlab.example.com/zhangweijie/tool-sdk/middleware/logger"
	"time"
)

type Recognizer struct {
	WgScan           sizedwaitgroup.SizedWaitGroup // 控制协程并发数量
	Limiter          *ratelimit.Limiter            // 控制单位时间内的发包数量
	RecognizeResults *result.RecognizeResult       // 识别结果
	Nmap             *nmap.Nmap                    // Nmap实例
}

// NewRecognizer 初始化识别器
func NewRecognizer(ctx context.Context) *Recognizer {
	recognizer := &Recognizer{
		RecognizeResults: result.NewRecognizeResult(),
		// 控制协程并发数量
		WgScan: sizedwaitgroup.New(global.DefaultRateConnectScan),
		// ratelimit 是一个用于限制请求速率的库。它提供了一种方便的方式来管理和控制在给定时间段内可以发送多少个请求。
		Limiter: ratelimit.New(ctx, uint(global.DefaultRateConnectScan), time.Second),
	}

	return recognizer
}

func (r *Recognizer) RecognizeService(ip string, port int) {
	defer r.WgScan.Done()
	defer func() {
		if err := recover(); err != nil {
			logger.Warn(fmt.Sprintf("IP：%s, PORT:%d, 服务识别过程中的出现问题: %s", ip, port, err))
			return
		}
	}()
	r.Limiter.Take()
	status, response := r.Nmap.ScanService(ip, port)
	if status == result.Matched || status == result.NotMatched {
		if response == nil {
			response = result.NewResponse(ip, port, status)
		}
		if response.Fingerprint.Service == "" {
			response.Fingerprint.Service = r.Nmap.GuessService(port)
		}
		if response.Fingerprint.Service == "http" || response.Fingerprint.Service == "https" {
			response.Protocol = response.Fingerprint.Service
		}
		response.Status = status.String()
		r.RecognizeResults.AddRecognizeResponse(ip, port, response)
	}
}
