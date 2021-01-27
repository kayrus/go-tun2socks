package tun

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/tun"
)

func setInterface(name string, mtu int, tun *tun.NativeTun, routes []*net.IPNet) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to detect %s interface: %s", name, err)
	}

	err = netlink.LinkSetMTU(link, mtu)
	if err != nil {
		return fmt.Errorf("failed to set MTU on %s interface: %s", name, err)
	}

	for _, r := range routes {
		ipv4Addr := &netlink.Addr{
			IPNet: r,
		}
		err = netlink.AddrAdd(link, ipv4Addr)
		if err != nil {
			return fmt.Errorf("failed to set peer address on %s interface: %s", name, err)
		}
	}

	err = netlink.LinkSetUp(link)
	if err != nil {
		return fmt.Errorf("failed to set %s interface up: %s", name, err)
	}

	return nil
}
