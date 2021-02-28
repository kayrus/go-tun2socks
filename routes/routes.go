package routes

import (
	"fmt"
	"net"
	"strings"

	"github.com/IBM/netaddr"
	"github.com/eycorsican/go-tun2socks/common/log"
)

func splitFunc(c rune) bool {
	return c == ',' || c == ' '
}

func getNet(v interface{}) *net.IPNet {
	switch v := v.(type) {
	case net.IP:
		return &net.IPNet{IP: v, Mask: net.CIDRMask(32, 32)}
	case *net.IPNet:
		return v
	}
	return nil
}

func Get(routes, excludeRoutes, addr, gw, mask string) (net.IP, []*net.IPNet, error) {
	excludeAddrs, err := ParseAddresses(addr, gw, mask)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid addresses: %v", err)
	}

	res := &netaddr.IPSet{}
	for _, cidr := range strings.FieldsFunc(routes, splitFunc) {
		if v := net.ParseIP(cidr).To4(); v != nil {
			res.InsertNet(getNet(v))
			log.Debugf("including %s to routes", v)
			continue
		}

		_, v, err := net.ParseCIDR(cidr)
		if err != nil {
			// trying to lookup a hostname
			if ips, err := net.LookupIP(cidr); err == nil {
				for _, v := range ips {
					if v := v.To4(); v != nil {
						log.Debugf("including %s (%s) to routes", cidr, v)
						res.InsertNet(getNet(v))
					}
				}
				continue
			} else {
				return nil, nil, fmt.Errorf("failed to resolve %q: %v", cidr, err)
			}
			return nil, nil, fmt.Errorf("failed to parse %s CIDR: %v", cidr, err)
		}
		log.Debugf("including %s to routes", v)
		res.InsertNet(v)
	}

	for _, cidr := range strings.FieldsFunc(excludeRoutes, splitFunc) {
		if v := net.ParseIP(cidr).To4(); v != nil {
			res.RemoveNet(getNet(v))
			log.Debugf("excluding %s from routes", v)
			continue
		}

		_, v, err := net.ParseCIDR(cidr)
		if err != nil {
			// trying to lookup a hostname
			if ips, err := net.LookupIP(cidr); err == nil {
				for _, v := range ips {
					if v := v.To4(); v != nil {
						log.Debugf("excluding %s (%s) from routes", cidr, v)
						res.RemoveNet(getNet(v))
					}
				}
				continue
			} else {
				return nil, nil, fmt.Errorf("failed to resolve %q: %v", cidr, err)
			}
			return nil, nil, fmt.Errorf("failed to parse %s CIDR: %v", cidr, err)
		}
		log.Debugf("excluding %s from routes", v)
		res.RemoveNet(v)
	}

	for _, cidr := range excludeAddrs {
		res.RemoveNet(cidr)
	}

	gateway := excludeAddrs[1]
	return gateway.IP, res.GetNetworks(), nil
}

func Set(name string, gw net.IP, routes []*net.IPNet) {
	for _, cidr := range routes {
		if err := routeAdd(cidr, gw, 0, name); err != nil {
			log.Errorf("failed to set %s routes: %v", name, err)
		}
	}
}

func Unset(name string, gw net.IP, routes []*net.IPNet) {
	for _, cidr := range routes {
		if err := routeDel(cidr, gw, 0, name); err != nil {
			log.Errorf("failed to unset %s routes: %v", name, err)
		}
	}
}

func ParseAddresses(addr, gw, mask string) ([]*net.IPNet, error) {
	local := net.ParseIP(addr)
	if local == nil {
		return nil, fmt.Errorf("invalid local IP address")
	}
	remote := net.ParseIP(gw)
	if remote == nil {
		return nil, fmt.Errorf("invalid server IP address")
	}
	remoteMask := net.ParseIP(mask)
	if remoteMask == nil {
		return nil, fmt.Errorf("invalid server IP mask")
	}

	return []*net.IPNet{
		getNet(local),
		{IP: remote, Mask: net.IPMask(remoteMask.To4())},
	}, nil
}
