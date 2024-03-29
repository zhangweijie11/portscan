package infodetect

import (
	"context"
	"errors"
	"fmt"
	"gitlab.example.com/zhangweijie/portscan/global"
	"gitlab.example.com/zhangweijie/portscan/middlerware/schemas"
	"gitlab.example.com/zhangweijie/portscan/services/common"
	"gitlab.example.com/zhangweijie/portscan/services/infodetect/banner"
	"gitlab.example.com/zhangweijie/portscan/services/infodetect/result"
	"gitlab.example.com/zhangweijie/portscan/services/infodetect/utils"
	"gitlab.example.com/zhangweijie/portscan/services/pportscan"
	"gitlab.example.com/zhangweijie/portscan/services/pportscan/portlist"
	"gitlab.example.com/zhangweijie/portscan/services/service_recognize"
	"gitlab.example.com/zhangweijie/portscan/services/service_recognize/nmap"
	serviceResult "gitlab.example.com/zhangweijie/portscan/services/service_recognize/result"
	toolGlobal "gitlab.example.com/zhangweijie/tool-sdk/global"
	toolSchemas "gitlab.example.com/zhangweijie/tool-sdk/middleware/schemas"
	toolModels "gitlab.example.com/zhangweijie/tool-sdk/models"
	"math/rand"
	"strconv"
	"sync"
	"time"
)

type Worker struct {
	ID         int // 任务执行者 ID
	Ctx        context.Context
	Wg         *sync.WaitGroup
	TaskChan   chan Task                      // 子任务通道
	ResultChan chan result.WorkerDetectResult // 子任务结果通道
}

type Task struct {
	WorkUUID    string                  // 总任务 UUID
	TaskUUID    string                  // 子任务 UUID
	TargetIps   []string                // 子任务目标 IP
	TargetPorts []*portlist.Port        // 子任务目标端口
	ValidParams *schemas.PortScanParams // 任务全部参数
	Nmap        *nmap.Nmap              // 执行 Nmap
}

// NewWorker 初始化 worker
func NewWorker(ctx context.Context, wg *sync.WaitGroup, id int, taskChan chan Task, resultChan chan result.WorkerDetectResult) *Worker {
	return &Worker{
		ID:         id,
		Ctx:        ctx,
		Wg:         wg,
		TaskChan:   taskChan,
		ResultChan: resultChan,
	}
}

// calculateChanCap 计算任务通道和结果通道的容量
func calculateChanCap(ipLength, portLength int) int {
	ipLen := (ipLength + global.DefaultIpGroupCount) / global.DefaultIpGroupCount
	portLen := (portLength + global.DefaultPortGroupCount) / global.DefaultPortGroupCount

	return ipLen * portLen
}

func mergeResult(portScanIpStatus map[string]string, serviceRecognizeResult map[string]map[int]*serviceResult.RecognizeResponse) result.WorkerDetectResult {
	var detectResult result.WorkerDetectResult
	detectResult.IpType = portScanIpStatus
	for ip, recognizeResult := range detectResult.ServiceRecognizeResult {
		if len(recognizeResult) > 0 {
			detectResult.IpType[ip] = "isValuable"
		}
	}

	detectResult.ServiceRecognizeResult = serviceRecognizeResult

	return detectResult
}

// GroupPortScanWorker 真正的执行 worker, 端口扫描只需要部分属性数据，不需要获取全部信息
func (w *Worker) GroupPortScanWorker() {
	go func() {
		defer w.Wg.Done()

		for task := range w.TaskChan {
			select {
			case <-w.Ctx.Done():
				return
			default:
				// 获取开放端口和对应协议
				portScanResult := pportscan.GetOpenPort(w.Ctx, task.TargetIps, task.TargetPorts, task.ValidParams)

				// 进行服务识别
				serviceRecognizeScanResult := service_recognize.GetService(w.Ctx, portScanResult.IpPorts, task.Nmap)

				// 整合数据
				workerDetectResult := mergeResult(portScanResult.PortScanIpStatus, serviceRecognizeScanResult)

				// 向结果通道推送数据
				w.ResultChan <- workerDetectResult
			}
		}
	}()
}

// InfoDetectMainWorker  端口扫描主程序
func InfoDetectMainWorker(ctx context.Context, work *toolModels.Work, validParams *schemas.PortScanParams) error {
	quit := make(chan struct{})
	errChan := make(chan error, 2)

	go func() {
		defer close(quit)
		defer close(errChan)

		scanType := banner.ShowNetworkCapabilities(validParams.ScanType)
		validParams.ScanType = scanType
		validIps, err := utils.SplitAndParseIP(validParams.IP)
		if err != nil {
			errChan <- err
		}
		validPorts, err := utils.SplitAndParsePort(validParams.Port)
		if err != nil {
			errChan <- err
		}
		source := rand.NewSource(time.Now().UnixNano())
		rng := rand.New(source)

		// 随机打乱 IP 和端口
		rng.Shuffle(len(validIps), func(i, j int) {
			validIps[i], validIps[j] = validIps[j], validIps[i]
		})

		rng.Shuffle(len(validPorts), func(i, j int) {
			validPorts[i], validPorts[j] = validPorts[j], validPorts[i]
		})

		// 自适应计算通道的容量
		maxBufferSize := calculateChanCap(len(validIps), len(validPorts))
		onePercent := float64(100 / maxBufferSize)
		taskChan := make(chan Task, maxBufferSize)
		resultChan := make(chan result.WorkerDetectResult, maxBufferSize)
		var wg sync.WaitGroup
		// 创建并启动多个工作者
		for i := 0; i < toolGlobal.Config.Server.Worker; i++ {
			worker := NewWorker(ctx, &wg, i, taskChan, resultChan)
			worker.GroupPortScanWorker()
			wg.Add(1)
		}

		customNmap := common.CustomerNmap
		// 生产者向任务通道发送任务
		go func() {
			// 通知消费者所有任务已经推送完毕
			defer close(taskChan)
			count := 0
			// 超出限制端口数量，则拆分端口进行异步任务操作
			for portStart := 0; portStart < len(validPorts); portStart += global.DefaultPortGroupCount {
				portEnd := portStart + global.DefaultPortGroupCount
				if portEnd > len(validPorts) {
					portEnd = len(validPorts)
				}
				// 超出限制的 IP 数量，则拆分 IP 进行异步任务操作
				for ipStart := 0; ipStart < len(validIps); ipStart += global.DefaultIpGroupCount {
					ipEnd := ipStart + global.DefaultIpGroupCount
					if ipEnd > len(validIps) {
						ipEnd = len(validIps)
					}
					task := Task{
						WorkUUID:    work.UUID,
						TaskUUID:    strconv.Itoa(count),
						TargetIps:   validIps[ipStart:ipEnd],
						TargetPorts: validPorts[portStart:portEnd],
						ValidParams: validParams,
						Nmap:        customNmap,
					}
					taskChan <- task
					count += 1
				}
			}
		}()
		// 等待所有工作者完成任务
		go func() {
			wg.Wait()
			close(resultChan)
		}()

		// 中间需要进行数据结构转换
		tmpResult := result.NewWorkerDetectResult()
		// 回收结果
		for workerDetectResult := range resultChan {
			for ip, portResponse := range workerDetectResult.ServiceRecognizeResult {
				// 第一次获取到数据，给个默认值
				if tmpResult.IpType[ip] == "" {
					tmpResult.IpType[ip] = workerDetectResult.IpType[ip]
				}
				// 后续获取到数据后，other 作为基础默认值，其他的值都可以对他进行覆盖
				if (tmpResult.IpType[ip] == "other" || tmpResult.IpType[ip] == "") && workerDetectResult.IpType[ip] != "other" {
					tmpResult.IpType[ip] = workerDetectResult.IpType[ip]
				}
				// 为了以防万一，将有数据的全部设为有效
				if len(portResponse) > 0 {
					tmpResult.IpType[ip] = "isValuable"
				}
				for port, response := range portResponse {
					tmpResult.AddServiceRecognizeResult(ip, port, response)
				}
			}
			if work.ProgressType != "" && work.ProgressUrl != "" {
				pushProgress := &toolGlobal.Progress{WorkUUID: work.UUID, ProgressType: work.ProgressType, ProgressUrl: work.ProgressUrl, Progress: 0}
				pushProgress.Progress += onePercent
				// 回传进度
				toolGlobal.ValidProgressChan <- pushProgress
			}
		}

		baseFinalResult := make(map[string]result.InfoDetectResult)

		var finalResult []result.InfoDetectResult
		for _, ip := range validIps {
			infoDetectResult := result.InfoDetectResult{Ip: ip, IpType: "other"}
			baseFinalResult[ip] = infoDetectResult
		}
		for ip, serviceRecognizeResult := range tmpResult.ServiceRecognizeResult {
			var portResult []*serviceResult.RecognizeResponse
			for _, response := range serviceRecognizeResult {
				portResult = append(portResult, response)
			}
			infoDetectResult := result.InfoDetectResult{
				Ip:         ip,
				IpType:     tmpResult.IpType[ip],
				PortResult: portResult,
			}
			baseFinalResult[ip] = infoDetectResult
		}

		for _, baseResult := range baseFinalResult {
			finalResult = append(finalResult, baseResult)
		}

		if work.CallbackType != "" && work.CallbackUrl != "" {
			pushResult := &toolGlobal.Result{WorkUUID: work.UUID, CallbackType: work.CallbackType, CallbackUrl: work.CallbackUrl, Result: map[string]interface{}{"result": finalResult}}
			// 回传结果
			toolGlobal.ValidResultChan <- pushResult
		}
	}()

	select {
	case <-ctx.Done():
		return errors.New(toolSchemas.WorkCancelErr)
	case <-quit:
		return nil
	case err := <-errChan:
		return err
	}
}

// HostDiscoverMainWorker  主机发现主程序
func HostDiscoverMainWorker(ctx context.Context, work *toolModels.Work, validParams *schemas.HostDiscoverParams) error {
	quit := make(chan struct{})
	errChan := make(chan error, 2)

	go func() {
		defer close(quit)
		defer close(errChan)

		scanType := banner.ShowNetworkCapabilities(validParams.ScanType)
		validParams.ScanType = scanType
		validIps, err := utils.SplitAndParseIP(validParams.IP)
		if err != nil {
			errChan <- err
		}
		source := rand.NewSource(time.Now().UnixNano())
		rng := rand.New(source)

		// 随机打乱 IP 和端口
		rng.Shuffle(len(validIps), func(i, j int) {
			validIps[i], validIps[j] = validIps[j], validIps[i]
		})

		if !(validParams.HostDiscover.ArpPing || validParams.HostDiscover.IPv6NeighborDiscoveryPing || validParams.HostDiscover.IcmpAddressMaskRequestProbe ||
			validParams.HostDiscover.IcmpEchoRequestProbe || validParams.HostDiscover.IcmpTimestampRequestProbe || len(validParams.HostDiscover.TcpAckPingProbes) > 0 ||
			len(validParams.HostDiscover.TcpAckPingProbes) > 0) {
			validParams.HostDiscover.IcmpEchoRequestProbe = true
			validParams.HostDiscover.IcmpTimestampRequestProbe = true
			validParams.HostDiscover.TcpSynPingProbes = append(validParams.HostDiscover.TcpSynPingProbes, "80")
			validParams.HostDiscover.TcpSynPingProbes = append(validParams.HostDiscover.TcpSynPingProbes, "443")
			validParams.HostDiscover.TcpAckPingProbes = append(validParams.HostDiscover.TcpAckPingProbes, "80")
			validParams.HostDiscover.TcpAckPingProbes = append(validParams.HostDiscover.TcpAckPingProbes, "443")
		}

		hostDiscoverResult := pportscan.GetHostDiscover(ctx, validIps, validParams)
		for _, ip := range validIps {
			if hostDiscoverResult.PortScanIpStatus[ip] == "active" {
				fmt.Println("------------>", ip)
			}
		}

		if work.CallbackType != "" && work.CallbackUrl != "" {
			pushResult := &toolGlobal.Result{WorkUUID: work.UUID, CallbackType: work.CallbackType, CallbackUrl: work.CallbackUrl, Result: map[string]interface{}{"result": hostDiscoverResult.PortScanIpStatus}}
			// 回传结果
			toolGlobal.ValidResultChan <- pushResult
		}
	}()

	select {
	case <-ctx.Done():
		return errors.New(toolSchemas.WorkCancelErr)
	case <-quit:
		return nil
	case err := <-errChan:
		return err
	}
}
