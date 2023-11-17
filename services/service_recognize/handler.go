package service_recognize

import (
	"context"
	"gitlab.example.com/zhangweijie/portscan/services/service_recognize/nmap"
	rr "gitlab.example.com/zhangweijie/portscan/services/service_recognize/recognizer"
	"gitlab.example.com/zhangweijie/portscan/services/service_recognize/result"
)

func GetService(ctx context.Context, portScanResults map[string][]int, nmap *nmap.Nmap) map[string]map[int]*result.RecognizeResponse {
	recognizer := rr.NewRecognizer(ctx)
	recognizer.Nmap = nmap
	for ip, ports := range portScanResults {
		for _, port := range ports {
			select {
			case <-ctx.Done():
				return recognizer.RecognizeResults.RecognizeResponses
			default:
				recognizer.WgScan.Add()
				go recognizer.RecognizeService(ip, port)
			}
		}
	}

	recognizer.WgScan.Wait()

	return recognizer.RecognizeResults.RecognizeResponses
}
