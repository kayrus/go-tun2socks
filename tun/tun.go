package tun

import (
	"io"
	"net"

	"golang.zx2c4.com/wireguard/tun"
)

func OpenTunDevice(name string, mtu int, routes []*net.IPNet, dnsServers []string) (io.ReadWriteCloser, error) {
	tunDev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, err
	}

	getName, err := tunDev.Name()
	if err != nil {
		return nil, err
	}

	return &tunnel{Device: tunDev}, setInterface(getName, mtu, tunDev.(*tun.NativeTun), routes)
}
