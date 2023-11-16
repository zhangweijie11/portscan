//go:build windows

package privileges

// IsPrivileged 在Windows上并不重要，因为使用的是连接扫描
func isPrivileged() bool {
	return false
}
