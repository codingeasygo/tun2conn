package tun2conn

import (
	"fmt"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/codingeasygo/tun2conn/dnsgw"
	"github.com/codingeasygo/util/xio"
	"github.com/codingeasygo/util/xio/frame"
	"github.com/songgao/water"
	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func init() {
	go http.ListenAndServe(":6063", nil)
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

type forwardPiper struct {
	xio.Piper
}

func (f *forwardPiper) PipeConn(conn io.ReadWriteCloser, target string) (err error) {
	err = f.Piper.PipeConn(frame.NewRawReadWriteCloser(frame.NewDefaultHeader(), conn, 2048), target)
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
	gw := NewGateway(device, "10.1.1.1/24", "10.1.1.1")
	gw.Cache = "cache"
	gw.Dialer = xio.PiperDialerF(func(uri string, bufferSize int) (raw xio.Piper, err error) {
		if uri == "tcp://dnsgw" {
			raw = &forwardPiper{Piper: dnsgw.NewGateway(1)}
			return
		}
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

	{ //tcp
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

	{ //udp
		text, err := exec.Command("bash", "-c", "dig example.com @10.1.1.1").CombinedOutput()
		if err != nil {
			t.Error(err)
			return
		}
		fmt.Printf("result is %v\n", string(text))
	}

	gw.Stop()

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{Response: true, Authoritative: true},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName("example.com."),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("example.com."),
					Type:  dnsmessage.TypeCNAME,
					Class: dnsmessage.ClassINET,
				},
				Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("a.example.com.")},
			},
			{
				Header: dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("a.example.com."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				},
				Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
			},
			{
				Header: dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("a.example.com."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				},
				Body: &dnsmessage.AAAAResource{AAAA: [16]byte{127, 0, 0, 2, 127, 0, 0, 2, 127, 0, 0, 2, 127, 0, 0, 2}},
			},
		},
	}
	pack, err := msg.Pack()
	if err != nil {
		t.Error(err)
		return
	}
	gw.dnsCache.Add(pack)

	{ //policy dns
		gw.Policy = func(on string, ip net.IP, port uint16, domain, cname string, questions []string) (string, net.IP, uint16) {
			return questions[0], nil, 0
		}
		key := gw.policyDNS(1, []string{"example.com"})
		if key != "example.com" {
			t.Error("error")
			return
		}
	}

	{ //policy udp
		gw.Policy = func(on string, ip net.IP, port uint16, domain, cname string, questions []string) (string, net.IP, uint16) {
			if cname == "example.com." {
				return cname, nil, 0
			}
			return "", nil, 0
		}
		uri, _, _ := gw.policyUDP(1, net.ParseIP("127.0.0.1"), 10, nil)
		if uri != "example.com." {
			t.Error("errror")
			return
		}
	}

	{ //policy tcp
		gw.Policy = func(on string, ip net.IP, port uint16, domain, cname string, questions []string) (string, net.IP, uint16) {
			if cname == "example.com." {
				return cname, nil, 0
			}
			return "", nil, 0
		}
		uri := gw.policyTCP(net.ParseIP("127.0.0.1"), 0)
		if uri != "example.com." {
			t.Error("errror")
			return
		}
	}

	{ //policy mode
		gw.Mode = ProxyAllMode
		uri, _, _ := gw.PolicyGFW("tcp", net.ParseIP("127.0.0.1"), 0, "example.com", "", nil)
		if uri != ".*->tcp://127.0.0.1:0" {
			t.Error("errror")
			return
		}

		gw.Mode = ProxyNoneMode
		uri, _, _ = gw.PolicyGFW("tcp", net.ParseIP("127.0.0.1"), 0, "example.com", "", nil)
		if uri != "tcp://127.0.0.1:0" {
			t.Error("errror")
			return
		}
	}

	gw6 := NewGateway(device, "2001:db8:0:1:1:1:1:1/24", "2001:db8:0:1:1:1:1:1")
	err = gw6.Start()
	if err != nil {
		t.Error(err)
		return
	}
	gw6.Stop()

	//cover
	gw.link.ARPHardwareType()
	gw.link.IsAttached()
	gw.link.Wait()
	gw.link.ParseHeader(nil)
	gw.link.AddHeader(nil)
	gw.link.Recv(nil)
	gw.link.Recv([]byte{1})
	gw.link.Recv([]byte{6 << 4})
	pkts := stack.PacketBufferList{}
	pkts.PushBack(stack.NewPacketBuffer(stack.PacketBufferOptions{}))
	gw.link.send = func(b []byte) tcpip.Error { return &tcpip.ErrAborted{} }
	gw.link.WritePackets(pkts)

	gw.udpConn.WriteTo([]byte(""), nil, nil)

	id := newGwConnID("tcp", &tcpip.FullAddress{}, &tcpip.FullAddress{})
	id.LocalAddr()
	fmt.Printf("-->%v\n", id)

	addr := newGwAddr("tcp", &tcpip.FullAddress{})
	addr.Network()
	fmt.Printf("-->%v\n", addr)

	pconn := newGwConnPacketConn("test", gw, gw.udpConn)
	pconn.LocalAddr()
	pconn.SetDeadline(time.Now())
	pconn.SetReadDeadline(time.Now())
	pconn.SetWriteDeadline(time.Now())

	//
	if gw := NewGateway(device, "10.1.1.1/xx", "10.1.1.1"); gw.Start() == nil {
		t.Error("error")
	}
	if gw := NewGateway(device, "10.1.1.x/24", "10.1.1.1"); gw.Start() == nil {
		t.Error("error")
	}
	if gw := NewGateway(device, "xxx", "10.1.1.1"); gw.Start() == nil {
		t.Error("error")
	}
	if gw := NewGateway(device, "10.1.1.1/24", "10.1.1.x"); gw.Start() == nil {
		t.Error("error")
	}

	gw1 := NewGateway(device, "10.1.1.1/24", "10.1.1.1")
	gw1.MAC = ""
	if gw1.Start() == nil {
		t.Error("error")
	}

	gw2 := NewGateway(device, "10.1.1.1/24", "10.1.1.1")
	gw2.Stack.CreateNIC(1, gw.link)
	if gw2.Start() == nil {
		t.Error("error")
	}

	connTCP := gwConnTCP{ep: &errEP{}}
	connTCP.Write([]byte("abc"))

	//bind error
	maddr, _ := net.ParseMAC("aa:00:01:01:01:01")
	gw3 := NewGateway(device, "10.1.1.1/24", "10.1.1.1")
	gw3.link = NewLinkEndpoint(uint32(gw3.MTU), tcpip.LinkAddress(maddr), gw3.writeDevice)
	if xerr := gw3.Stack.CreateNIC(2, gw3.link); xerr != nil {
		t.Error(err)
		return

	}
	gw3.proto = ipv4.ProtocolNumber
	if err = gw3.startDNS(); err != nil {
		t.Error(err)
		return
	}
	if gw3.Start() == nil {
		t.Error("error")
		return
	}
	gw3.stopDNS()
	gw3.Stop()

	//new error
	gw4 := NewGateway(device, "10.1.1.1/24", "10.1.1.1")
	gw4.Stack = stack.New(stack.Options{})
	if gw4.Start() == nil {
		t.Error("error")
		return
	}
	gw4.startDNS()
	gw4.startUDP()
	gw4.startTCP()
	gw4.Stop()
	gw4 = NewGateway(device, "10.1.1.1/24", "10.1.1.1")
	gw4.Start()
	_, err = newGwListenerTCP(gw4, gw4.proto, gw4.Dialer, gw4.BufferSize)
	if err == nil {
		t.Error(err)
		return
	}
	gw4.Stop()

	//
	gw.device = &errWriter{}
	gw.writeDevice([]byte("error"))

	//panic
	gw.tcpGw.Dialer = nil
	gw.tcpGw.waiter.Add(1)
	gw.tcpGw.procConn(gw.tcpGw.ep, gw.tcpGw.wq)
}

type errEP struct {
	tcpip.Endpoint
}

func (e *errEP) Write(tcpip.Payloader, tcpip.WriteOptions) (int64, tcpip.Error) {
	return 0, &tcpip.ErrAborted{}
}

type errWriter struct {
	io.ReadWriteCloser
}

func (e *errWriter) Write(p []byte) (n int, err error) {
	err = fmt.Errorf("test error")
	return
}

func TestGatewayByListen(t *testing.T) {
	gw, err := NewGatewayByListen("udp", "127.0.0.1:0", "10.1.1.1/24", "10.1.1.1")
	if err != nil {
		t.Error(err)
		return
	}
	err = gw.Start()
	if err != nil {
		t.Error(err)
		return
	}
	gw.Stop()

	device := gw.device.(*PacketConnDevice)
	device.Write(nil)
	device.fromAddr = &net.TCPAddr{}
	device.Write(nil)
}

func TestGatewayByFile(t *testing.T) {
	NewGatewayByFile(0, "10.1.1.1/24", "10.1.1.1")
}
