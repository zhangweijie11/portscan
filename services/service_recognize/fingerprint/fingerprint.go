package fingerprint

type Technology struct {
	Name       string   `json:"name"`       // 名称
	Version    string   `json:"version"`    // 版本
	Categories []string `json:"categories"` // 类别列表
}

type Fingerprint struct {
	// Nmap 服务识别指纹库中的信息
	//  p/vendorproductname/
	//	v/version/
	//	i/info/
	//	h/hostname/
	//	o/operatingsystem/
	//	d/devicetype/
	ProbeName        string       `json:"probeName"`        //探针名称
	MatchRegexString string       `json:"matchRegexString"` //匹配规则正则表达式
	Service          string       `json:"service"`          //服务
	Info             string       `json:"info"`             //详细信息
	Hostname         string       `json:"hostname"`         //主机名称
	OperatingSystem  string       `json:"operatingSystem"`  //操作系统
	DeviceType       string       `json:"deviceType"`       //设备类型
	ProductName      string       `json:"productName"`      //Nmap 服务指纹库中产品名称
	Version          string       `json:"version"`          //Nmap 服务指纹库中版本
	Technologies     []Technology `json:"technologies"`     //前置的指纹识别数据，方便后边合并
}
