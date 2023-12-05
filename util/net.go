package util

import (
	"bytes"
	"fmt"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"github.com/codingeasygo/tun2conn/log"
)

func runCommand(format string, args ...interface{}) (text string, err error) {
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
	text = strings.TrimSpace(buffer.String())
	return
}

type Network struct {
	Gateway    bool //if enable to set new gateway
	Log        bool
	ifac       *Interface
	defaultGW  string
	defaultDEV string
	name       string
	netAddr    string
	netMask    int
	gwAddr     string
}

func LoadNetwork(name string, netAddr string, netMask int, gwAddr string) (n *Network, err error) {
	n = &Network{
		ifac:    NewInterface(name),
		name:    name,
		netAddr: netAddr,
		netMask: netMask,
		gwAddr:  gwAddr,
	}
	err = n.init()
	return
}

func (n *Network) init() (err error) {
	var ip, dev string
	switch runtime.GOOS {
	case "darwin":
		ip, err = n.ifac.run("route -n get default | grep 'gateway' | awk '{print $2}'")
		if err == nil {
			dev, err = n.ifac.run("route -n get default | grep 'interface' | awk '{print $2}'")
		}
	case "linux":
		ip, err = n.ifac.run("ip r | awk '/^def/{print $3}'")
		if err == nil {
			dev, err = n.ifac.run("ip r | awk '/^def/{print $5}'")
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
	err = n.ifac.AddAddress(n.netAddr, n.netMask, n.gwAddr)
	switch runtime.GOOS {
	case "darwin":
		if n.Gateway && err == nil {
			_, err = n.ifac.run("route delete default %v", n.defaultGW)
		}
		if n.Gateway && err == nil {
			_, err = n.ifac.run("route add default %v", n.gwAddr)
		}
	case "linux":

		if n.Gateway && err == nil {
			_, err = n.ifac.run("ip route replace default via %v dev %v", n.gwAddr, n.name)
		}
	default:
		err = fmt.Errorf("%v is not supported", runtime.GOOS)
	}
	return
}

func (n *Network) AddRouter(netAddr string, netMask int) (err error) {
	err = n.ifac.AddRouter(netAddr, netMask, n.defaultGW)
	return
}

func (n *Network) RemoveRouter(netAddr string, netMask int) (err error) {
	err = n.ifac.RemoveRouter(netAddr, netMask, n.defaultGW)
	return
}

func (n *Network) Reset() (err error) {
	switch runtime.GOOS {
	case "darwin":
		if n.Gateway && err == nil {
			_, err = n.ifac.run("route delete default %v", n.gwAddr)
		}
		if n.Gateway && err == nil {
			_, err = n.ifac.run("route add default %v", n.defaultGW)
		}
	case "linux":
		if n.Gateway && err == nil {
			_, err = n.ifac.run("ip route replace default via %v dev %v", n.defaultGW, n.defaultDEV)
		}
	default:
		err = fmt.Errorf("%v is not supported", runtime.GOOS)
	}
	return
}

func (n *Network) String() string {
	return fmt.Sprintf("Network(%v/%v)", n.defaultDEV, n.defaultGW)
}

type Interface struct {
	Log   bool
	name  string
	added map[string]int
	lock  sync.RWMutex
}

func NewInterface(name string) (ifac *Interface) {
	ifac = &Interface{
		name:  name,
		added: map[string]int{},
		lock:  sync.RWMutex{},
	}
	return
}

func (n *Interface) run(format string, args ...interface{}) (out string, err error) {
	out, err = runCommand(format, args...)
	if n.Log {
		log.DebugLog("Interface run (%v) => %v", fmt.Sprintf(format, args...), out)
	}
	return
}

func (n *Interface) AddAddress(netAddr string, netMask int, gwAddr string) (err error) {
	n.lock.Lock()
	defer func() {
		if err == nil {
			key := fmt.Sprintf("%v/%v", netAddr, netMask)
			n.added[key] = 1
		}
		n.lock.Unlock()
	}()

	added := len(n.added)
	switch runtime.GOOS {
	case "darwin":
		if err == nil {
			if added > 0 {
				_, err = n.run("ifconfig %v alias %v/%v %v up", n.name, netAddr, netMask, gwAddr)
			} else {
				_, err = n.run("ifconfig %v %v/%v %v up", n.name, netAddr, netMask, gwAddr)
			}
		}
		if err == nil {
			_, err = n.run("route add -net %v/%v -interface %v", netAddr, netMask, n.name)
		}
	case "linux":
		if err == nil {
			_, err = n.run("ip addr add %v/%v dev %v", netAddr, netMask, n.name)
		}
		if err == nil {
			_, err = n.run("ip link set dev %v up", n.name)
		}
	default:
		err = fmt.Errorf("%v is not supported", runtime.GOOS)
	}
	return
}

func (n *Interface) RemoveAddress(netAddr string, netMask int, gwAddr string) (err error) {
	n.lock.Lock()
	defer func() {
		if err == nil {
			key := fmt.Sprintf("%v/%v", netAddr, netMask)
			delete(n.added, key)
		}
		n.lock.Unlock()
	}()
	added := len(n.added)
	switch runtime.GOOS {
	case "darwin":
		if err == nil {
			if added > 1 {
				_, err = n.run("ifconfig %v alias %v/%v down", n.name, netAddr, netMask)
			} else {
				_, err = n.run("ifconfig %v %v/%v %v down", n.name, netAddr, netMask, gwAddr)
			}
		}
		if err == nil {
			_, err = n.run("route delete -net %v/%v -interface %v", netAddr, netMask, n.name)
		}
	case "linux":
		if err == nil {
			_, err = n.run("ip addr del %v/%v dev %v", netAddr, netMask, n.name)
		}
		if err == nil {
			if added == 1 {
				_, err = n.run("ip link set dev %v down", n.name)
			}
		}
	default:
		err = fmt.Errorf("%v is not supported", runtime.GOOS)
	}
	return
}

func (n *Interface) AddRouter(netAddr string, netMask int, gwAddr string) (err error) {
	switch runtime.GOOS {
	case "darwin":
		_, err = n.run("route -n add %v/%v %v", netAddr, netMask, gwAddr)
	case "linux":
		_, err = n.run("ip route add %v/%v via %v", netAddr, netMask, gwAddr)
	default:
		err = fmt.Errorf("%v is not supported", runtime.GOOS)
	}
	return
}

func (n *Interface) RemoveRouter(netAddr string, netMask int, gwAddr string) (err error) {
	switch runtime.GOOS {
	case "darwin":
		_, err = n.run("route -n delete %v/%v %v", netAddr, netMask, gwAddr)
	case "linux":
		_, err = n.run("ip route del %v/%v via %v", netAddr, netMask, gwAddr)
	default:
		err = fmt.Errorf("%v is not supported", runtime.GOOS)
	}
	return
}
