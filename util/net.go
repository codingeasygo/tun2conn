package util

import (
	"bytes"
	"fmt"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"

	"github.com/codingeasygo/tun2conn/log"
)

type Network struct {
	defaultGW  string
	defaultDEV string
	name       string
	netAddr    string
	netMask    int
	gwAddr     string
}

func LoadNetwork(name string, netAddr string, netMask int, gwAddr string) (n *Network, err error) {
	n = &Network{
		name:    name,
		netAddr: netAddr,
		netMask: netMask,
		gwAddr:  gwAddr,
	}
	err = n.init()
	return
}

func (n *Network) run(format string, args ...interface{}) (out string, err error) {
	script := fmt.Sprintf(format, args...)
	buffer := bytes.NewBuffer(nil)
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/C", script)
	default:
		cmd = exec.Command("bash", "-c", script)
	}
	cmd.Stdout = buffer
	cmd.Stderr = buffer
	err = cmd.Run()
	out = strings.TrimSpace(buffer.String())
	log.DebugLog("Net run (%v) => %v", script, out)
	return
}

func (n *Network) init() (err error) {
	var ip, dev string
	switch runtime.GOOS {
	case "darwin":
		ip, err = n.run("route -n get default | grep 'gateway' | awk '{print $2}'")
		if err == nil {
			dev, err = n.run("route -n get default | grep 'interface' | awk '{print $2}'")
		}
	case "linux":
		ip, err = n.run("ip r | awk '/^def/{print $3}'")
		if err == nil {
			dev, err = n.run("ip r | awk '/^def/{print $5}'")
		}
	default:
		err = fmt.Errorf("not support %v", runtime.GOOS)
	}
	if err != nil {
		return
	}
	ip = strings.TrimSpace(ip)
	dev = strings.TrimSpace(dev)
	if len(ip) < 1 {
		err = fmt.Errorf("default gateway is not found")
		return
	}
	_, err = netip.ParseAddr(ip)
	if err != nil {
		err = fmt.Errorf("default gateway is not found")
		return
	}
	n.defaultGW, n.defaultDEV = ip, dev
	return
}

func (n *Network) Setup() (err error) {
	switch runtime.GOOS {
	case "darwin":
		if err == nil {
			_, err = n.run("ifconfig %v %v/%v %v up", n.name, n.netAddr, n.netMask, n.gwAddr)
		}
		if err == nil {
			_, err = n.run("route add -net %v/%v -interface %v", n.netAddr, n.netMask, n.name)
		}
		if err == nil {
			_, err = n.run("route delete default %v", n.defaultGW)
		}
		if err == nil {
			_, err = n.run("route add default %v", n.gwAddr)
		}
	case "linux":
		if err == nil {
			_, err = n.run("ip addr add %v/%v dev %v", n.netAddr, n.netMask, n.name)
		}
		if err == nil {
			_, err = n.run("ip link set dev %v up", n.name)
		}
		if err == nil {
			_, err = n.run("ip route replace default via %v dev %v", n.gwAddr, n.name)
		}
	default:
		err = fmt.Errorf("%v is not supported", runtime.GOOS)
	}
	return
}

func (n *Network) Add(netAddr string, netMask int) (err error) {
	switch runtime.GOOS {
	case "darwin":
		_, err = n.run("route -n add %v/%v %v", netAddr, netMask, n.defaultGW)
	case "linux":
		_, err = n.run("ip route add %v/%v via %v", netAddr, netMask, n.defaultGW)
	default:
		err = fmt.Errorf("%v is not supported", runtime.GOOS)
	}
	return
}

func (n *Network) Remove(netAddr string, netMask int) (err error) {
	switch runtime.GOOS {
	case "darwin":
		_, err = n.run("route -n delete %v/%v %v", netAddr, netMask, n.defaultGW)
	case "linux":
		_, err = n.run("ip route del %v/%v via %v", netAddr, netMask, n.defaultGW)
	default:
		err = fmt.Errorf("%v is not supported", runtime.GOOS)
	}
	return
}

func (n *Network) Reset() (err error) {
	switch runtime.GOOS {
	case "darwin":
		_, err = n.run("route delete default %v", n.gwAddr)
		if err == nil {
			_, err = n.run("route add default %v", n.defaultGW)
		}
	case "linux":
		_, err = n.run("ip route replace default via %v dev %v", n.defaultGW, n.defaultDEV)
	default:
		err = fmt.Errorf("%v is not supported", runtime.GOOS)
	}
	return
}

func (n *Network) String() string {
	return fmt.Sprintf("Network(%v/%v)", n.defaultDEV, n.defaultGW)
}
