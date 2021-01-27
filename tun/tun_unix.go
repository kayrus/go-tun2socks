// +build darwin freebsd

package tun

import (
	"fmt"
	"net"
	"os/exec"

	"golang.zx2c4.com/wireguard/tun"
)

func setInterface(name string, mtu int, tun *tun.NativeTun, routes []*net.IPNet) error {
	args := []string{
		name,
		"mtu",
		fmt.Sprintf("%d", mtu),
	}
	v, err := exec.Command("ifconfig", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set MTU: %s: %s: %s", args, v, err)
	}

	for _, r := range routes {
		args = []string{
			name,
			"inet",
			r.String(),
			"add",
		}
		v, err = exec.Command("ifconfig", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to set ip addr: %s: %s: %s", args, v, err)
		}
	}
	args = []string{
		name,
		"up",
	}
	v, err = exec.Command("ifconfig", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to bring up interface: %s: %s: %s", args, v, err)
	}

	return nil
}
