package schemas

var taskValidatorErrorMessage = map[string]string{
	"IPrequired":   "缺少任务 IP",
	"Portrequired": "缺少任务端口",
	"CDN":          "请选择是否排除 CDN IP",   // 是否排除 CDN
	"WAF":          "请选择是否排除 WAF IP",   // 是否排除 WAF
	"Cloud":        "请选择是否排除 Cloud IP", // 是否排除 Cloud
}

// RegisterValidatorRule 注册参数验证错误消息, Key = e.StructNamespace(), value.key = e.Field()+e.Tag()
var RegisterValidatorRule = map[string]map[string]string{
	"PortScanParams":     taskValidatorErrorMessage,
	"HostDiscoverParams": taskValidatorErrorMessage,
}
