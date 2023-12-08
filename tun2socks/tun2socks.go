package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/codingeasygo/tun2conn"
	"github.com/codingeasygo/tun2conn/log"
	"github.com/codingeasygo/tun2conn/udpgw"
	"github.com/codingeasygo/util/proxy/socks"
	"github.com/codingeasygo/util/xio"
	"github.com/codingeasygo/util/xio/frame"
	"github.com/songgao/water"
)

var server bool
var socksAddr string
var netAddr string
var gwAddr string

func init() {
	flag.BoolVar(&server, "s", false, "start socks server")
	flag.StringVar(&socksAddr, "socks", "127.0.0.1:1010", "the socks address")
	flag.StringVar(&netAddr, "net", "10.1.0.2", "the net interface address")
	flag.StringVar(&gwAddr, "gw", "10.1.0.1", "the gateway address")
	flag.Parse()
}

func main() {
	if server {
		runServer()
	} else {
		runClient()
	}
}

type udpgwGateway struct {
	*udpgw.Gateway
	BufferSize int
}

func (u *udpgwGateway) PipeConn(conn io.ReadWriteCloser, target string) (err error) {
	return u.Gateway.PipeConn(frame.NewReadWriteCloser(frame.NewDefaultHeader(), conn, u.BufferSize), target)
}

func runServer() {
	log.InfoLog("tun2socks start server on %v", socksAddr)
	server := socks.NewServer()
	server.Dialer = xio.PiperDialerF(func(uri string, bufferSize int) (raw xio.Piper, err error) {
		if strings.HasPrefix(uri, "tcp://udpgw") {
			raw = &udpgwGateway{Gateway: udpgw.NewGateway(), BufferSize: bufferSize}
		} else {
			raw, err = xio.DialNetPiper(uri, bufferSize)
		}
		log.InfoLog("tun2socks dial %v with %v", uri, err)
		return
	})
	err := server.Run(socksAddr)
	fmt.Printf("socks server stop by %v\n", err)
	log.InfoLog("tun2socks server is stopped by %v", err)
}

func runClient() {
	TestGateway(nil)

	// log.InfoLog("tun2socks start client by socks:%v,net:%v,gw:%v", socksAddr, netAddr, gwAddr)

	// if len(socksAddr) < 1 {
	// 	panic("socks address is required")
	// }
	// socksAddress, err := net.ResolveTCPAddr("tcp", socksAddr)
	// if err != nil {
	// 	panic(err)
	// }
	// dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, nil)
	// if err != nil {
	// 	panic(err)
	// }

	// device, err := water.New(water.Config{
	// 	DeviceType: water.TUN,
	// })
	// if err != nil {
	// 	panic(err)
	// }

	// log.InfoLog("tun2socks create device %v success", device.Name())

	// defaultGW, err := util.LoadNetwork(device.Name(), netAddr, 24, gwAddr)
	// if err != nil {
	// 	panic(err)
	// }
	// defaultGW.Gateway = true
	// defer func() {
	// 	defaultGW.RemoveRouter(socksAddress.IP.String(), 32)
	// 	defaultGW.Reset()
	// }()
	// log.InfoLog("tun2socks load network %v success", defaultGW)

	// err = defaultGW.Setup()
	// if err != nil {
	// 	panic(err)
	// }
	// log.InfoLog("tun2socks setup device %v success", device.Name())

	// err = defaultGW.AddRouter(socksAddress.IP.String(), 32)
	// if err != nil {
	// 	panic(err)
	// }
	// log.InfoLog("tun2socks add socks addr %v to route success", socksAddress.IP)

	// gw := tun2conn.NewGateway(device, fmt.Sprintf("%v/24", gwAddr), gwAddr)
	// gw.Dialer = xio.PiperDialerF(func(uri string, bufferSize int) (raw xio.Piper, err error) {
	// 	parts := strings.SplitN(uri, "://", 2)
	// 	if len(parts) < 2 {
	// 		err = fmt.Errorf("invalid uri %v", uri)
	// 		return
	// 	}
	// 	var conn io.ReadWriteCloser
	// 	if parts[1] == "udpgw" {
	// 		conn, err = dialer.Dial(parts[0], "udpgw:1")
	// 		if err == nil {
	// 			conn = frame.NewReadWriteCloser(frame.NewDefaultHeader(), conn, bufferSize)
	// 		}
	// 	} else {
	// 		conn, err = dialer.Dial(parts[0], parts[1])
	// 	}
	// 	if err == nil {
	// 		raw = xio.NewCopyPiper(conn, bufferSize)
	// 	}
	// 	return
	// })
	// err = gw.Start()
	// if err != nil {
	// 	panic(err)
	// }

	// sigc := make(chan os.Signal, 1)
	// signal.Notify(sigc,
	// 	syscall.SIGHUP,
	// 	syscall.SIGINT,
	// 	syscall.SIGTERM,
	// 	syscall.SIGQUIT)
	// <-sigc

	// gw.Stop()

	// log.InfoLog("tun2socks client is stopped by %v", err)
}

func runConfig(name, netAddr, gwAddr string) (err error) {
	args := []string{}
	switch runtime.GOOS {
	case "darwin":
		setupScript := fmt.Sprintf(`ifconfig %v %v/24 %v up && route add -net %v/24 -interface %v`, name, netAddr, gwAddr, netAddr, name)
		args = append(args, "bash", "-c", setupScript)
	case "linux":
		setupScript := fmt.Sprintf(`ip addr add %v/24 dev %v && ip link set dev %v up`, netAddr, name, name)
		args = append(args, "bash", "-c", setupScript)
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	return
}

func TestGateway(t *testing.T) {
	// maddr, _ := net.ParseMAC("aa:00:01:01:01:01")
	device, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		t.Error(err)
		return
	}
	err = runConfig(device.Name(), "10.1.1.2", "10.1.1.1")
	if err != nil {
		t.Error(err)
		return
	}
	var dialErrr error
	gw := tun2conn.NewGateway(device, "10.1.1.1/24", "10.1.1.1")
	gw.Dialer = xio.PiperDialerF(func(uri string, bufferSize int) (raw xio.Piper, err error) {
		if dialErrr != nil {
			err = dialErrr
			return
		}
		if strings.Contains(uri, "10.1.1.6") {
			err = fmt.Errorf("test error")
			return
		}
		fmt.Printf("dial to %v\n", uri)
		raw = xio.NewEchoPiper(bufferSize)
		return
	})
	err = gw.Start()
	if err != nil {
		t.Error(err)
		return
	}

	if false { //tcp
		conn, err := net.Dial("tcp", "10.1.1.1:1000")
		if err != nil {
			t.Error(err)
			return
		}
		fmt.Fprintf(conn, "abc")

		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			t.Error(err)
			return
		}
		fmt.Printf("read->%v\n", buffer[0:n])
		conn.Close()

		conn, err = net.Dial("tcp", "10.1.1.6:1000")
		if err != nil {
			t.Error(err)
			return
		}
		_, err = conn.Read(buffer)
		if err == nil {
			t.Error(err)
			return
		}

		_, err = net.Dial("tcp", "10.1.1.1:1001") //not close
		if err != nil {
			t.Error(err)
			return
		}
	}

	{ //udp
		conn, err := net.Dial("udp", "10.1.1.1:1000")
		if err != nil {
			t.Error(err)
			return
		}
		fmt.Fprintf(conn, "abc")

		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			t.Error(err)
			return
		}
		fmt.Printf("read->%v\n", buffer[0:n])
		conn.Close()
	}

	// { //udp
	// 	text, err := exec.Command("bash", "-c", "dig example.com @10.1.1.1").CombinedOutput()
	// 	if err != nil {
	// 		t.Error(err)
	// 		return
	// 	}
	// 	fmt.Printf("result is %v\n", string(text))
	// }

	gw.Stop()
}
