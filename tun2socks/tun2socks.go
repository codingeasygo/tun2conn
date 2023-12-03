package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/codingeasygo/tun2conn"
	"github.com/codingeasygo/tun2conn/log"
	"github.com/codingeasygo/tun2conn/udpgw"
	"github.com/codingeasygo/tun2conn/util"
	"github.com/codingeasygo/util/proxy/socks"
	"github.com/codingeasygo/util/xio"
	"github.com/codingeasygo/util/xio/frame"
	"github.com/songgao/water"
	"golang.org/x/net/proxy"
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
	log.InfoLog("tun2socks start client by socks:%v,net:%v,gw:%v", socksAddr, netAddr, gwAddr)

	if len(socksAddr) < 1 {
		panic("socks address is required")
	}
	socksAddress, err := net.ResolveTCPAddr("tcp", socksAddr)
	if err != nil {
		panic(err)
	}
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, nil)
	if err != nil {
		panic(err)
	}

	device, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		panic(err)
	}

	log.InfoLog("tun2socks create device %v success", device.Name())

	defaultGW, err := util.LoadNetwork(device.Name(), netAddr, 24, gwAddr)
	if err != nil {
		panic(err)
	}
	defer func() {
		defaultGW.Remove(socksAddress.IP.String(), 32)
		defaultGW.Reset()
	}()
	log.InfoLog("tun2socks load network %v success", defaultGW)

	err = defaultGW.Setup()
	if err != nil {
		panic(err)
	}
	log.InfoLog("tun2socks setup device %v success", device.Name())

	err = defaultGW.Add(socksAddress.IP.String(), 32)
	if err != nil {
		panic(err)
	}
	log.InfoLog("tun2socks add socks addr %v to route success", socksAddress.IP)

	gw := tun2conn.NewGateway(device, fmt.Sprintf("%v/24", gwAddr), "")
	gw.Dialer = xio.PiperDialerF(func(uri string, bufferSize int) (raw xio.Piper, err error) {
		parts := strings.SplitN(uri, "://", 2)
		if len(parts) < 2 {
			err = fmt.Errorf("invalid uri %v", uri)
			return
		}
		var conn io.ReadWriteCloser
		if parts[1] == "udpgw" {
			conn, err = dialer.Dial(parts[0], "udpgw:1")
			if err == nil {
				conn = frame.NewReadWriteCloser(frame.NewDefaultHeader(), conn, bufferSize)
			}
		} else {
			conn, err = dialer.Dial(parts[0], parts[1])
		}
		if err == nil {
			raw = xio.NewCopyPiper(conn, bufferSize)
		}
		return
	})
	err = gw.Start()
	if err != nil {
		panic(err)
	}

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	<-sigc

	gw.Stop()

	log.InfoLog("tun2socks client is stopped by %v", err)
}
