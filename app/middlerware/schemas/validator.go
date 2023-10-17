package schemas

var taskValidatorErrorMessage = map[string]string{
	"iprequired":   "缺少任务 IP",
	"portrequired": "缺少任务端口",
}

// RegisterValidatorRule 注册参数验证错误消息, Key = e.StructNamespace(), value.key = e.Field()+e.Tag()
var RegisterValidatorRule = map[string]map[string]string{
	"PortScanParams": taskValidatorErrorMessage,
}
