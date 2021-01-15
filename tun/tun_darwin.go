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

	v, err := exec.Command("ifconfig", name, "mtu", fmt.Sprintf("%d", mtu)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set MTU: %s: %s", v, err)
	}
	v, err = exec.Command("ifconfig", name, "inet", addrs[0].String(), addrs[1].String()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set ip addr: %s: %s", v, err)
	}
	v, err = exec.Command("ifconfig", name, "up").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to bring up interface: %s: %s", v, err)
	}

	return nil
}
