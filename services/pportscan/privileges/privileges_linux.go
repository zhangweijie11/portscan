//go:build linux || unix

package privileges

import (
	"os"
	"runtime"

	"app/global/israce"
	"golang.org/x/sys/unix"
)

// isPrivileged 查当前进程是否具有CAP_NET_RAW功能或为 root 用户
func isPrivileged() bool {
	// runtime.LockOSThread interferes with race detection
	if !israce.Enabled {
		header := unix.CapUserHeader{
			Version: unix.LINUX_CAPABILITY_VERSION_3,
			Pid:     int32(os.Getpid()),
		}
		data := unix.CapUserData{}
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		if err := unix.Capget(&header, &data); err == nil {
			data.Inheritable = (1 << unix.CAP_NET_RAW)

			if err := unix.Capset(&header, &data); err == nil {
				return true
			}
		}
	}
	return os.Geteuid() == 0
}
