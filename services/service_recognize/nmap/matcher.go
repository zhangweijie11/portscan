package nmap

import (
	"fmt"
	"gitlab.example.com/zhangweijie/portscan/global/utils"
	servicefinger "gitlab.example.com/zhangweijie/portscan/services/service_recognize/fingerprint"
	"gitlab.example.com/zhangweijie/tool-sdk/middleware/logger"
	"regexp"
	"strconv"
	"strings"
)

type Matcher struct {
	//match <Service> <pattern> <patternopt> [<versioninfo>]
	//是否为模糊匹配
	soft bool
	//服务
	service string
	//规则
	pattern string
	//规则正则
	patternRegexp *regexp.Regexp
	//版本信息
	versionInfo *servicefinger.Fingerprint
}

var matchVersionInfoHelperRegxP = regexp.MustCompile(`\$P\((\d)\)`)
var matchVersionInfoHelperRegx = regexp.MustCompile(`\$(\d)`)

var matchLoadRegexps = []*regexp.Regexp{
	regexp.MustCompile("^([a-zA-Z0-9-_./]+) m\\|([^|]+)\\|([is]{0,2})(?: (.*))?$"),
	regexp.MustCompile("^([a-zA-Z0-9-_./]+) m=([^=]+)=([is]{0,2})(?: (.*))?$"),
	regexp.MustCompile("^([a-zA-Z0-9-_./]+) m%([^%]+)%([is]{0,2})(?: (.*))?$"),
	regexp.MustCompile("^([a-zA-Z0-9-_./]+) m@([^@]+)@([is]{0,2})(?: (.*))?$"),
}

var matchVersionInfoRegexps = map[string]*regexp.Regexp{
	"PRODUCTNAME": regexp.MustCompile("p/([^/]+)/"),
	"VERSION":     regexp.MustCompile("v/([^/]+)/"),
	"INFO":        regexp.MustCompile("i/([^/]+)/"),
	"HOSTNAME":    regexp.MustCompile("h/([^/]+)/"),
	"OS":          regexp.MustCompile("o/([^/]+)/"),
	"DEVICE":      regexp.MustCompile("d/([^/]+)/"),
}

// @Title: parseMatch
// @Description: 解析匹配规则
// @param commandArgs: eg. jsonrpc m|^{"jsonrpc":"([\d.]+)".*|s v/$1/
// @param soft: false
// @return *match:
func parseMatch(commandArgs string, soft bool) *Matcher {
	var match = &Matcher{}
	var regx *regexp.Regexp

	for _, re := range matchLoadRegexps {
		if re.MatchString(commandArgs) {
			regx = re
		}
	}

	//eg.  regx = ^([a-zA-Z0-9-_./]+) m\|([^|]+)\|([is]{0,2})(?: (.*))?$
	if regx == nil {
		logger.Warn("match 语句参数不正确")
	}

	//eg. args = [jsonrpc m|^{"jsonrpc":"([\d.]+)".*|s v/$1/ jsonrpc ^{"jsonrpc":"([\d.]+)".* s v/$1/]
	args := regx.FindStringSubmatch(commandArgs)
	match.soft = soft
	match.service = args[1]
	//eg. jsonrpc
	match.service = utils.FixService(match.service)
	//eg. ^{"jsonrpc":"([\d.]+)".*
	match.pattern = args[2]
	match.patternRegexp = match.getPatternRegexp(match.pattern, args[3])
	match.versionInfo = &servicefinger.Fingerprint{
		ProbeName:        "",
		MatchRegexString: "",
		Service:          match.service,
		Info:             match.getVersionInfo(commandArgs, "INFO"),
		Hostname:         match.getVersionInfo(commandArgs, "HOSTNAME"),
		OperatingSystem:  match.getVersionInfo(commandArgs, "OS"),
		DeviceType:       match.getVersionInfo(commandArgs, "DEVICE"),
		ProductName:      match.getVersionInfo(commandArgs, "PRODUCTNAME"),
		Version:          match.getVersionInfo(commandArgs, "VERSION"),
	}
	return match
}

// @Title: getPatternRegexp
// @Description: 获取匹配规则正则表达式
// @receiver m:
// @param pattern: eg. ^{"jsonrpc":"([\d.]+)".*
// @param opt: eg. s
// @return *regexp.Regexp:
func (m *Matcher) getPatternRegexp(pattern string, opt string) *regexp.Regexp {
	pattern = strings.ReplaceAll(pattern, `\0`, `\x00`)
	if opt != "" {
		if strings.Contains(opt, "i") == false {
			opt += "i"
		}
		if pattern[:1] == "^" {
			pattern = fmt.Sprintf("^(?%s:%s", opt, pattern[1:])
		} else {
			pattern = fmt.Sprintf("(?%s:%s", opt, pattern)
		}
		if pattern[len(pattern)-1:] == "$" {
			pattern = fmt.Sprintf("%s)$", pattern[:len(pattern)-1])
		} else {
			pattern = fmt.Sprintf("%s)", pattern)
		}
	}
	//eg. pattern = ^(?si:{"jsonrpc":"([\d.]+)".*)
	return regexp.MustCompile(pattern)
}

// getVersionInfo  获取版本信息
func (m *Matcher) getVersionInfo(commandArgs string, regID string) string {
	if matchVersionInfoRegexps[regID].MatchString(commandArgs) {
		return matchVersionInfoRegexps[regID].FindStringSubmatch(commandArgs)[1]
	} else {
		return ""
	}
}

// makeVersionInfoSubHelper  整合版本信息
func (m *Matcher) makeVersionInfoSubHelper(responseData string, pattern string) string {
	if len(m.patternRegexp.FindStringSubmatch(responseData)) == 1 {
		return pattern
	}
	if pattern == "" {
		return pattern
	}
	sArr := m.patternRegexp.FindStringSubmatch(responseData)

	if matchVersionInfoHelperRegxP.MatchString(pattern) {
		pattern = matchVersionInfoHelperRegxP.ReplaceAllStringFunc(pattern, func(repl string) string {
			a := matchVersionInfoHelperRegxP.FindStringSubmatch(repl)[1]
			return "$" + a
		})
	}

	if matchVersionInfoHelperRegx.MatchString(pattern) {
		pattern = matchVersionInfoHelperRegx.ReplaceAllStringFunc(pattern, func(repl string) string {
			i, _ := strconv.Atoi(matchVersionInfoHelperRegx.FindStringSubmatch(repl)[1])
			return sArr[i]
		})
	}
	pattern = strings.ReplaceAll(pattern, "\n", "")
	pattern = strings.ReplaceAll(pattern, "\r", "")
	return pattern
}

// makeVersionInfo  整合版本信息
func (m *Matcher) makeVersionInfo(responseData string, fingerPrint *servicefinger.Fingerprint) {
	fingerPrint.Info = m.makeVersionInfoSubHelper(responseData, m.versionInfo.Info)
	fingerPrint.DeviceType = m.makeVersionInfoSubHelper(responseData, m.versionInfo.DeviceType)
	fingerPrint.Hostname = m.makeVersionInfoSubHelper(responseData, m.versionInfo.Hostname)
	fingerPrint.OperatingSystem = m.makeVersionInfoSubHelper(responseData, m.versionInfo.OperatingSystem)
	fingerPrint.Service = m.makeVersionInfoSubHelper(responseData, m.versionInfo.Service)
	// 当产品名称为空时，不入库
	if m.makeVersionInfoSubHelper(responseData, m.versionInfo.ProductName) != "" {
		fingerPrint.Technologies = append(fingerPrint.Technologies, servicefinger.Technology{
			Name:       m.makeVersionInfoSubHelper(responseData, m.versionInfo.ProductName),
			Version:    m.makeVersionInfoSubHelper(responseData, m.versionInfo.Version),
			Categories: []string{"product"},
		})
	}
}
