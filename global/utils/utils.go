package utils

import (
	"fmt"
	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
	"gitlab.example.com/zhangweijie/tool-sdk/global"
	"gitlab.example.com/zhangweijie/tool-sdk/middleware/logger"
	"path/filepath"
	"regexp"
	"strings"
)

// GetAreaOfIP  根据 IP 获取省市区地址
func GetAreaOfIP(ip string) (map[string]string, error) {
	result := map[string]string{"country": "", "province": "", "city": "", "district": "", "provider": ""}

	var dbPath = filepath.Join(global.Config.Server.RootDir, "data/ip2region/ip2region.xdb")
	// 备注：并发使用，每个 goroutine 需要创建一个独立的 searcher 对象。
	searcher, err := xdb.NewWithFileOnly(dbPath)
	if err != nil {
		logger.Error("创建 IP 地址搜索器失败: %s\n", err)
		return result, err
	}

	defer searcher.Close()
	// do the search
	searchRegion, err := searcher.SearchByStr(ip)
	if err != nil {
		fmt.Printf("failed to SearchIP(%s): %s\n", ip, err)
		return result, err
	}
	splitSearchRegion := strings.Split(searchRegion, "|")
	if splitSearchRegion[0] != "0" && len(splitSearchRegion) > 0 {
		result["country"] = splitSearchRegion[0]
	}
	if splitSearchRegion[2] != "0" && len(splitSearchRegion) > 2 {
		result["province"] = splitSearchRegion[2]
	}
	if splitSearchRegion[3] != "0" && len(splitSearchRegion) > 3 {
		result["city"] = splitSearchRegion[3]
	}
	if splitSearchRegion[4] != "0" && len(splitSearchRegion) > 4 {
		result["provider"] = splitSearchRegion[4]
	}
	return result, nil
}

var regexpFirstNum = regexp.MustCompile(`^\d`)

// FixService  统一输出服务名称
func FixService(oldService string) string {
	//进行最后输出修饰
	if oldService == "ssl/http" {
		return "https"
	}
	if oldService == "http-proxy" {
		return "http"
	}
	if oldService == "ms-wbt-server" {
		return "rdp"
	}
	if oldService == "microsoft-ds" {
		return "smb"
	}
	if oldService == "netbios-ssn" {
		return "netbios"
	}
	if oldService == "oracle-tns" {
		return "oracle"
	}
	if oldService == "msrpc" {
		return "rpc"
	}
	if oldService == "ms-sql-s" {
		return "mssql"
	}
	if oldService == "domain" {
		return "dns"
	}
	if oldService == "svnserve" {
		return "svn"
	}
	if oldService == "ibm-db2" {
		return "db2"
	}
	if oldService == "socks-proxy" {
		return "socks5"
	}
	if len(oldService) > 4 {
		if oldService[:4] == "ssl/" {
			return oldService[4:] + "-ssl"
		}
	}
	if regexpFirstNum.MatchString(oldService) {
		oldService = "S" + oldService
	}
	oldService = strings.ReplaceAll(oldService, "_", "-")
	return oldService
}
