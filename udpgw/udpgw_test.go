package udpgw

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	_ "net/http/pprof"
	"testing"
	"time"

	"github.com/codingeasygo/util/xhttp"
	"github.com/codingeasygo/util/xio"
	"github.com/codingeasygo/util/xio/frame"
)

func TestGateway(t *testing.T) {
	//ipv4
	lv4, _ := net.ListenUDP("udp4", nil)
	addrv4 := lv4.LocalAddr().(*net.UDPAddr)
	datav4 := make([]byte, 1024)
	lenv4 := 0
	binary.BigEndian.PutUint16(datav4[1:], 1)
	lenv4 += 3
	lenv4 += copy(datav4[lenv4:], addrv4.IP)
	binary.BigEndian.PutUint16(datav4[lenv4:], uint16(addrv4.Port))
	lenv4 += 2
	lenv4 += copy(datav4[lenv4:], []byte("abc"))
	go func() {
		buf := make([]byte, 1024)
		for {
			n, from, _ := lv4.ReadFromUDP(buf)
			lv4.WriteToUDP(buf[0:n], from)
		}
	}()
	//ipv6
	lv6, _ := net.ListenUDP("udp6", nil)
	addrv6 := lv6.LocalAddr().(*net.UDPAddr)
	datav6 := make([]byte, 1024)
	lenv6 := 0
	datav6[0] = CLIENT_FLAG_IPV6
	binary.BigEndian.PutUint16(datav6[1:], 2)
	lenv6 += 3
	lenv6 += copy(datav6[lenv6:], addrv6.IP)
	binary.BigEndian.PutUint16(datav6[lenv6:], uint16(addrv6.Port))
	lenv6 += 2
	lenv6 += copy(datav6[lenv6:], []byte("abc"))
	go func() {
		buf := make([]byte, 1024)
		for {
			n, from, _ := lv6.ReadFromUDP(buf)
			lv6.WriteToUDP(buf[0:n], from)
		}
	}()
	a, b, _ := xio.Pipe()
	gw := NewGateway()
	gw.DNS = addrv4
	gw2 := NewGateway()
	gw2.DNS = addrv4
	go gw.PipeConn(frame.NewReadWriteCloser(frame.NewDefaultHeader(), b, 1024), "tcp://localhost")
	//
	sender := frame.NewReadWriteCloser(frame.NewDefaultHeader(), a, 1024)
	var back []byte
	buffer := make([]byte, 1024)

	//ipv4
	for i := 0; i < 100; i++ {
		binary.BigEndian.PutUint16(datav4[1:], uint16(i))
		sender.Write(datav4[0:lenv4])
		back, _ = sender.ReadFrame()
		if !bytes.Equal(back[4:], datav4[:lenv4]) {
			fmt.Printf("back->%v,%v\n", back[4:], datav4[:lenv4])
			t.Error("error")
			return
		}

		gw2.Write(datav4[0:lenv4])
		n, _ := gw2.Read(buffer)
		if !bytes.Equal(buffer[:n], datav4[:lenv4]) {
			fmt.Printf("back->%v,%v\n", buffer[:n], datav4[:lenv4])
			t.Error("error")
			return
		}
	}

	//ipv6
	sender.Write(datav6[0:lenv6])
	back, _ = sender.ReadFrame()
	if !bytes.Equal(back[4:], datav6[:lenv6]) {
		fmt.Printf("back->%v,%v\n", back[4:], datav6[:lenv6])
		t.Error("error")
		return
	}
	//state
	ts := httptest.NewServer(http.HandlerFunc(StateH))
	xhttp.GetText("%v", ts.URL)
	//timeout
	StartTimeout(time.Millisecond, 10*time.Millisecond)
	func() {
		defer func() {
			recover()
		}()
		StartTimeout(time.Millisecond, 10*time.Millisecond)
	}()
	time.Sleep(100 * time.Millisecond)
	if len(gw.connList) > 0 {
		t.Error("error")
		return
	}
	StopTimeout()

	//dns
	datav4[0] = CLIENT_FLAG_DNS
	binary.BigEndian.PutUint16(datav4[1:], 3)
	sender.Write(datav4[0:lenv4])
	back, _ = sender.ReadFrame()
	if !bytes.Equal(back[4:], datav4[:lenv4]) {
		fmt.Printf("back->%v,%v\n", back[4:], datav4[:lenv4])
		t.Error("error")
		return
	}

	time.Sleep(1 * time.Second)

	//close
	sender.Close()
	gw.Close()

	time.Sleep(100 * time.Millisecond)

	//
	//test erro
	gw.PipeConn(&net.TCPConn{}, "")

	gw.recvData(nil, 0, nil)
	gw.recvData([]byte{CLIENT_FLAG_KEEPALIVE, 0, 0}, 0, nil)
	gw.recvData([]byte{0, 0, 100, 127, 0, 0, 5, 0, 0, 0, 0, 0}, 0, nil)
	gw.procRead(&gwConn{raw: &net.UDPConn{}}, 0, nil)

	DialGateway("test", 100)

	allGateway = map[string]*Gateway{"x": nil}
	procTimeout(time.Second)

	allGateway = map[string]*Gateway{}

	gw2.buffer = make(chan []byte, 1)
	gw2.sendData(nil)
	gw2.sendData(nil)
	gw2.Read(buffer)
	gw2.Close()
	gw2.Close()

	fmt.Printf("info is %v\n", gw2)
}

type testPacketConn struct {
	net.PacketConn
	LAddr *net.UDPAddr
	RAddr net.Addr
	Send  chan []byte
	Recv  chan []byte
	Done  chan int
}

func newTestPacketConn() (conn *testPacketConn) {
	conn = &testPacketConn{
		Send: make(chan []byte, 1),
		Recv: make(chan []byte, 1),
		Done: make(chan int, 1),
	}
	return
}

func (t *testPacketConn) Close() (err error) {
	t.Done <- 1
	return
}

func (t *testPacketConn) Network() string {
	return "pair"
}

func (t *testPacketConn) String() string {
	return "test"
}

func (t *testPacketConn) LocalAddr() net.Addr {
	return t.LAddr
}

func (t *testPacketConn) LocalIP() net.IP {
	return t.LAddr.IP
}

func (t *testPacketConn) LocalPort() uint16 {
	return uint16(t.LAddr.Port)
}

func (t *testPacketConn) RemoteAddr() net.Addr {
	return t.RAddr
}

func (t *testPacketConn) ReadFrom(p []byte) (n int, from net.Addr, err error) {
	data := <-t.Send
	if len(data) < 1 {
		err = fmt.Errorf("clsoed")
		return
	}
	copy(p, data)
	n = len(data)
	from = t
	return
}

func (t *testPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	data := make([]byte, len(p))
	copy(data, p)
	t.Recv <- data
	return
}

func TestConn(t *testing.T) {
	{
		lv4, _ := net.ListenUDP("udp4", nil)
		go func() {
			buffer := make([]byte, 1024)
			for {
				n, from, err := lv4.ReadFrom(buffer)
				if err != nil {
					break
				}
				lv4.WriteTo(buffer[:n], from)
			}
		}()
		fmt.Printf("lv4 start on %v\n", lv4.LocalAddr())
		gw := NewGateway()
		pc := newTestPacketConn()
		pc.LAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: lv4.LocalAddr().(*net.UDPAddr).Port}
		pc.RAddr = lv4.LocalAddr()
		conn := NewConn(pc, false)
		rwc := frame.NewRawReadWriteCloser(frame.NewDefaultHeader(), conn, 1024)
		go gw.PipeConn(rwc, "tcp://udpgw")
		pc.Send <- []byte("abc")
		data := <-pc.Recv
		if !bytes.Equal(data, []byte("abc")) {
			t.Errorf("recv:%x", string(data))
			return
		}
		pc.Send <- nil
		<-pc.Done
	}
	{
		lv6, _ := net.ListenUDP("udp6", nil)
		go func() {
			buffer := make([]byte, 1024)
			for {
				n, from, err := lv6.ReadFrom(buffer)
				if err != nil {
					break
				}
				lv6.WriteTo(buffer[:n], from)
			}
		}()
		fmt.Printf("lv6 start on %v\n", lv6.LocalAddr())
		gw := NewGateway()
		pc := newTestPacketConn()
		pc.LAddr = lv6.LocalAddr().(*net.UDPAddr)
		pc.RAddr = lv6.LocalAddr()
		conn := NewConn(pc, true)
		rwc := frame.NewRawReadWriteCloser(frame.NewDefaultHeader(), conn, 1024)
		go gw.PipeConn(rwc, "tcp://udpgw")
		pc.Send <- []byte("abc")
		data := <-pc.Recv
		if !bytes.Equal(data, []byte("abc")) {
			t.Errorf("recv:%x", string(data))
			return
		}
		pc.Send <- nil
		<-pc.Done
	}
	{
		pc := newTestPacketConn()
		conn := NewConn(pc, true)
		conn.Write(nil)
		conn.Write([]byte{CLIENT_FLAG_KEEPALIVE, 0, 1, 0, 0, 0, 0, 0, 0})
		conn.Write([]byte{0, 0, 1, 0, 0, 0, 0, 0, 0})
	}
	{
		pc := newTestPacketConn()
		conn := NewConn(pc, true)
		conn.addrAll[1] = pc
		conn.addrLast[1] = time.Now().Add(-time.Hour)
		conn.clearTimeoutLocked()
	}
}

type forwardPiper struct {
	xio.Piper
}

func (f *forwardPiper) PipeConn(conn io.ReadWriteCloser, target string) (err error) {
	err = f.Piper.PipeConn(frame.NewRawReadWriteCloser(frame.NewDefaultHeader(), conn, 2048), target)
	return
}

func TestForwarder(t *testing.T) {
	lv4, _ := net.ListenUDP("udp4", nil)
	go func() {
		buffer := make([]byte, 1024)
		for {
			n, from, err := lv4.ReadFrom(buffer)
			if err != nil {
				break
			}
			lv4.WriteTo(buffer[:n], from)
		}
	}()
	fmt.Printf("lv4 start on %v\n", lv4.LocalAddr())
	{ //normal
		pc := newTestPacketConn()
		pc.LAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: lv4.LocalAddr().(*net.UDPAddr).Port}
		pc.RAddr = lv4.LocalAddr()
		conn := NewConn(pc, false)

		dialer := xio.PiperDialerF(func(uri string, bufferSize int) (raw xio.Piper, err error) {
			raw = &forwardPiper{Piper: NewGateway()}
			return
		})
		forwarder := NewForwarder(dialer, 2048)
		forwarder.Policy = func(conid uint16, i net.IP, p uint16) (string, net.IP, uint16) { return "*", nil, 0 }
		go forwarder.ServeConn(conn)

		pc.Send <- []byte("abc")
		time.Sleep(time.Second)
		data := <-pc.Recv
		if !bytes.Equal(data, []byte("abc")) {
			t.Errorf("recv:%x", string(data))
			return
		}
		pc.Send <- nil

		conn.Close()
		<-pc.Done
	}
	{ //rewrite
		pc := newTestPacketConn()
		pc.LAddr = &net.UDPAddr{IP: net.ParseIP("1.0.0.1"), Port: lv4.LocalAddr().(*net.UDPAddr).Port}
		pc.RAddr = lv4.LocalAddr()
		conn := NewConn(pc, false)

		dialer := xio.PiperDialerF(func(uri string, bufferSize int) (raw xio.Piper, err error) {
			raw = &forwardPiper{Piper: NewGateway()}
			return
		})
		forwarder := NewForwarder(dialer, 2048)
		forwarder.Policy = func(conid uint16, i net.IP, p uint16) (string, net.IP, uint16) {
			return "*", net.ParseIP("127.0.0.1"), p
		}
		go forwarder.ServeConn(conn)

		pc.Send <- []byte("abc")
		time.Sleep(time.Second)
		data := <-pc.Recv
		if !bytes.Equal(data, []byte("abc")) {
			t.Errorf("recv:%x", string(data))
			return
		}
		pc.Send <- nil

		conn.Close()
		<-pc.Done
	}

	//test error
	{
		pc := newTestPacketConn()
		pc.LAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: lv4.LocalAddr().(*net.UDPAddr).Port}
		pc.RAddr = lv4.LocalAddr()
		conn := NewConn(pc, false)
		dialer := xio.PiperDialerF(func(uri string, bufferSize int) (raw xio.Piper, err error) {
			raw = &forwardPiper{Piper: NewGateway()}
			return
		})
		forwarder := NewForwarder(dialer, 2048)
		forwarder.Policy = func(conid uint16, i net.IP, p uint16) (string, net.IP, uint16) {
			return "*", net.ParseIP("127.0.0.1"), p
		}

		forwarder.procData(nil, nil)

		forwarder.procData(conn, []byte{CLIENT_FLAG_IPV6, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})

		forwarder.Policy = func(conid uint16, i net.IP, p uint16) (string, net.IP, uint16) { return "none", nil, 0 }
		forwarder.procData(conn, []byte{CLIENT_FLAG_IPV6, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})

		dialer = xio.PiperDialerF(func(uri string, bufferSize int) (raw xio.Piper, err error) {
			return nil, fmt.Errorf("test error")
		})
		forwarder = NewForwarder(dialer, 2048)
		forwarder.Policy = func(conid uint16, i net.IP, p uint16) (string, net.IP, uint16) { return "error", nil, 0 }
		forwarder.procData(conn, []byte{CLIENT_FLAG_IPV6, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})

		//cover
		fc := &forwarderConn{}
		fc.send([]byte("abc"))
		fc.send([]byte("abc"))
	}
}
