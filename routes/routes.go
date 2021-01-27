package routes

import (
	"fmt"
	"net"
	"strings"

	"github.com/IBM/netaddr"
	"github.com/eycorsican/go-tun2socks/common/log"
)

// excludeList is used, when the 0.0.0.0/0 traffic is routed through the tunnel
var excludeList = []string{
	"0.0.0.0/8",
	"127.0.0.0/8",
}

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

func Get(routes, excludeRoutes string) ([]*net.IPNet, error) {
	res := &netaddr.IPSet{}
	for _, cidr := range strings.FieldsFunc(routes, splitFunc) {
		if v := net.ParseIP(cidr).To4(); v != nil {
			res.InsertNet(getNet(v))
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
				return nil, fmt.Errorf("failed to resolve %q: %v", cidr, err)
			}
			return nil, fmt.Errorf("failed to parse %s CIDR: %v", cidr, err)
		}
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
				return nil, fmt.Errorf("failed to resolve %q: %v", cidr, err)
			}
			return nil, fmt.Errorf("failed to parse %s CIDR: %v", cidr, err)
		}
		log.Debugf("excluding %s from routes", v)
		res.RemoveNet(v)
	}

	for _, v := range excludeList {
		_, cidr, _ := net.ParseCIDR(v)
		res.RemoveNet(cidr)
	}

	return res.GetNetworks(), nil
}
