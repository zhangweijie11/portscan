//go:build darwin

package privileges

import (
	"os"
)

// isPrivileged 查当前进程是否具有CAP_NET_RAW功能或为 root 用户
func isPrivileged() bool {
	return os.Geteuid() == 0
}
