//go:build windows
// +build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

const (
	winTun     = "wintun.dll"
	winTunSite = "https://www.wintun.net/"
)

func checkPermissions() error {
	// https://github.com/golang/go/issues/28804#issuecomment-505326268
	var sid *windows.SID

	// https://docs.microsoft.com/en-us/windows/desktop/api/securitybaseapi/nf-securitybaseapi-checktokenmembership
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return fmt.Errorf("error while checking for elevated permissions: %s", err)
	}

	// We must free the sid to prevent security token leaks
	defer windows.FreeSid(sid)
	token := windows.Token(0)

	member, err := token.IsMember(sid)
	if err != nil {
		return fmt.Errorf("error while checking for elevated permissions: %s", err)
	}
	if !member {
		return fmt.Errorf("tun2socks needs to run with administrator permissions")
	}

	err = windows.NewLazyDLL(winTun).Load()
	if err != nil {
		dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
		if err != nil {
			dir = "tun2socks"
		}
		return fmt.Errorf("the %s was not found, you can download it from %s and place it into the %q directory", winTun, winTunSite, dir)
	}

	return nil
}
