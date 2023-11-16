package privileges

import osutil "github.com/projectdiscovery/utils/os"

var IsPrivileged bool
var IsOSSupported bool

func init() {
	IsPrivileged = isPrivileged()
	IsOSSupported = osutil.IsLinux() || osutil.IsOSX()
}
