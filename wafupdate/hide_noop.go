//go:build !windows && !darwin
// +build !windows,!darwin

package wafupdate

func hideFile(path string) error {
	return nil
}
