package service_recognize

import (
	"gitlab.example.com/zhangweijie/portscan/services/service_recognize/nmap"
	rr "gitlab.example.com/zhangweijie/portscan/services/service_recognize/recognizer"
	"gitlab.example.com/zhangweijie/portscan/services/service_recognize/result"
)

func GetService(portScanResults map[string][]int, nmap *nmap.Nmap) map[string]map[int]*result.Response {
	recognizer := rr.NewRecognizer()
	recognizer.Nmap = nmap
	for ip, ports := range portScanResults {
		for _, port := range ports {
			recognizer.WgScan.Add()
			go recognizer.RecognizeService(ip, port)
		}
	}

	recognizer.WgScan.Wait()

	return recognizer.RecognizeResults.RecognizeResponses
}
