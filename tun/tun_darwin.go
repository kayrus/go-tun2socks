package tun

import (
	"fmt"
	"os/exec"

	"github.com/eycorsican/go-tun2socks/routes"
	"golang.zx2c4.com/wireguard/tun"
)

func setInterface(name, addr, gw, mask string, mtu int, tun *tun.NativeTun) error {
	addrs, err := routes.ParseAddresses(addr, gw, mask)
	if err != nil {
		return err
	}

	args := []string{
		name,
		"mtu",
		fmt.Sprintf("%d", mtu),
	}
	v, err := exec.Command("ifconfig", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set MTU: %s: %s: %s", args, v, err)
	}
	args = []string{
		name,
		"inet",
		addrs[0].String(),
		addrs[1].String(),
	}
	v, err = exec.Command("ifconfig", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set ip addr: %s: %s: %s", args, v, err)
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
