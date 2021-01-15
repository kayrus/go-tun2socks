package routes

import (
	"fmt"
	"net"
	"os/exec"
)

var ifIndex int

func getIfID(name string) error {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("failed to find a %q interface index: %s", name, err)
	}

	ifIndex = iface.Index

	return nil
}

func routeAdd(dst interface{}, gw net.IP, priority int, name string) error {
	if ifIndex == 0 {
		if err := getIfID(name); err != nil {
			return err
		}
	}

	// an implementation of "replace"
	routeDel(dst, gw, priority, name)
	d := getNet(dst)
	args := []string{
		"add",
		d.IP.String(),
		"mask",
		net.IP(d.Mask).To4().String(),
		gw.String(),
		"metric",
		fmt.Sprintf("%d", priority+1),
		"if",
		fmt.Sprintf("%d", ifIndex),
	}
	v, err := exec.Command("route.exe", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add %s route to %s interface: %s: %s: %s", dst, name, args, v, err)
	}
	return nil
}

func routeDel(dst interface{}, gw net.IP, priority int, name string) error {
	d := getNet(dst)
	args := []string{
		"delete",
		d.IP.String(),
		"mask",
		net.IP(d.Mask).To4().String(),
		gw.String(),
		"metric",
		fmt.Sprintf("%d", priority+1),
		"if",
		fmt.Sprintf("%d", ifIndex),
	}
	v, err := exec.Command("route.exe", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to delete %s route from %s interface: %s: %s: %s", dst, name, args, v, err)
	}
	return nil
}
