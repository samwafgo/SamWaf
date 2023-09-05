//go:build !windows
// +build !windows

package wafupdate

func hideFile(path string) error {
	return nil
}
