package tun

import (
	"fmt"
	"net"
	"os/exec"

	"github.com/eycorsican/go-tun2socks/routes"
	"golang.zx2c4.com/wireguard/tun"
)

type tunnel struct {
	tun.Device
}

func (t *tunnel) Read(b []byte) (int, error) {
	return t.Device.Read(b, 0)
}

func (t *tunnel) Write(b []byte) (int, error) {
	return t.Device.Write(b, 0)
}

func (t *tunnel) Close() error {
	return t.Device.Close()
}

func setInterface(name, addr, gw, mask string, mtu int, tun *tun.NativeTun) error {
	args := []string{
		"interface",
		"ipv4",
		"set",
		"subinterface",
		name,
		fmt.Sprintf("mtu=%d", mtu),
		"store=persistent",
	}
	v, err := exec.Command("netsh.exe", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set MTU on %s interface: %s: %s: %s", name, args, v, err)
	}

	addrs, err := routes.ParseAddresses(addr, gw, mask)
	if err != nil {
		return err
	}
	args = []string{
		"interface",
		"ipv4",
		"set",
		"address",
		"name=" + name,
		"static",
		addrs[0].IP.String(),
		net.IP(addrs[1].Mask).To4().String(),
	}
	v, err = exec.Command("netsh.exe", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set tun interface: %s: %s: %s", args, v, err)
	}

	return nil
}
