//go:build !windows
// +build !windows

package main

import (
	"fmt"
	"os"
)

func checkPermissions() error {
	if uid := os.Getuid(); uid != 0 {
		return fmt.Errorf("tun2socks needs to run as root")
	}
	return nil
}
