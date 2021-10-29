//go:build linux || darwin || freebsd
// +build linux darwin freebsd

package core

/*
#cgo CFLAGS: -I./c/include
#include "lwip/init.h"
*/
import "C"

func lwipInit() {
	C.lwip_init() // Initialze modules.
}
