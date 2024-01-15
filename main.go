package main

import (
	"context"
	"encoding/json"
	"errors"
	"gitlab.example.com/zhangweijie/portscan/middlerware/schemas"
	_ "gitlab.example.com/zhangweijie/portscan/services/common"
	"gitlab.example.com/zhangweijie/portscan/services/infodetect"
	tool "gitlab.example.com/zhangweijie/tool-sdk/cmd"
	"gitlab.example.com/zhangweijie/tool-sdk/global"
	"gitlab.example.com/zhangweijie/tool-sdk/middleware/logger"
	toolSchemas "gitlab.example.com/zhangweijie/tool-sdk/middleware/schemas"
	toolModels "gitlab.example.com/zhangweijie/tool-sdk/models"
	"gitlab.example.com/zhangweijie/tool-sdk/option"
)

type executorIns struct {
	global.ExecutorIns
}

// ValidWorkCreateParams 验证任务参数
func (ei *executorIns) ValidWorkCreateParams(params map[string]interface{}) (err error) {
	var schema = new(schemas.HostDiscoverParams)
	err = toolSchemas.CustomBindSchema(params, schema, schemas.RegisterValidatorRule)
	return err
}

// ExecutorMainFunc 任务执行主函数（可自由发挥）
// params = map[string]interface{}{
// "work": &toolmodels.Work
// }
func (ei *executorIns) ExecutorMainFunc(ctx context.Context, params map[string]interface{}) error {
	errChan := make(chan error, 2)
	go func() {
		defer close(errChan)
		work := params["work"].(*toolModels.Work)
		switch work.WorkType {
		case "portscan":
			var validParams schemas.PortScanParams
			err := json.Unmarshal(work.Params, &validParams)
			if err != nil {
				logger.Error(toolSchemas.JsonParseErr, err)
				errChan <- err
			} else {
				err = infodetect.InfoDetectMainWorker(ctx, work, &validParams)
				errChan <- err
			}
		case "hostdiscover":
			var validParams schemas.HostDiscoverParams
			err := json.Unmarshal(work.Params, &validParams)
			if err != nil {
				logger.Error(toolSchemas.JsonParseErr, err)
				errChan <- err
			} else {
				err = infodetect.HostDiscoverMainWorker(ctx, work, &validParams)
				errChan <- err
			}
		}

	}()
	select {
	case <-ctx.Done():
		return errors.New(toolSchemas.WorkCancelErr)
	case err := <-errChan:
		return err
	}
}

func main() {
	defaultOption := option.GetDefaultOption()
	defaultOption.ExecutorIns = &executorIns{}
	tool.Start(defaultOption)
}
