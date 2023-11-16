package portlist

import (
	"gitlab.example.com/zhangweijie/tool-sdk/middleware/logger"
	"regexp"
	"strconv"
	"strings"
)

// 示例数据：80 或者 8000-9000
var portRangeRegx = regexp.MustCompile("^(\\d+)(?:-(\\d+))?$")

// 示例数据：80-90,100-200,300,400-405
var portGroupRegx = regexp.MustCompile("^(\\d+(?:-\\d+)?)(?:,\\d+(?:-\\d+)?)*$")

type PortList []int

var EmptyPortList = PortList([]int{})

// ParsePortList  解析端口列表，提取有效端口列表数据
func ParsePortList(commandArgs string) PortList {
	var portList = PortList([]int{})
	if portGroupRegx.MatchString(commandArgs) == false {
		logger.Warn("匹配字符串无效")
	}

	for _, expr := range strings.Split(commandArgs, ",") {
		rArr := portRangeRegx.FindStringSubmatch(expr)
		var startPort, endPort int
		startPort, _ = strconv.Atoi(rArr[1])
		if rArr[2] != "" {
			endPort, _ = strconv.Atoi(rArr[2])
		} else {
			endPort = startPort
		}
		for num := startPort; num <= endPort; num++ {
			portList = append(portList, num)
		}
	}
	portList = portList.RemoveDuplicate()
	return portList
}

// RemoveDuplicate  移除重复端口
func (p PortList) RemoveDuplicate() PortList {
	result := make([]int, 0, len(p))
	temp := map[int]struct{}{}
	for _, item := range p {
		if _, ok := temp[item]; !ok { //如果字典中找不到元素，ok=false，!ok为true，就往切片中append元素。
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

// Append  添加扫描端口
func (p PortList) Append(ports ...int) PortList {
	p = append(p, ports...)
	p = p.RemoveDuplicate()
	return p
}

// Exist  验证端口是否存在
func (p PortList) Exist(port int) bool {
	for _, num := range p {
		if num == port {
			return true
		}
	}
	return false
}
