package dnsgw

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/codingeasygo/util/xdebug"
	"github.com/codingeasygo/util/xio"
	"github.com/codingeasygo/util/xio/frame"
	"golang.org/x/net/dns/dnsmessage"
)

func init() {
	go http.ListenAndServe(":6063", nil)
}

func TestResolver(t *testing.T) {
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Error(err)
		return
	}
	port := ln.LocalAddr().(*net.UDPAddr).Port

	resolver := NewResolver()
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, from, err := ln.ReadFrom(buffer)
			if err != nil {
				break
			}
			response, err := resolver.Query(context.Background(), buffer[0:n])
			fmt.Println("Query--->", err)
			if len(response) > 0 {
				ln.WriteTo(response, from)
			}
		}
	}()
	time.Sleep(100 * time.Millisecond)

	for _, x := range strings.Split("A,NS,CNAME,MX,TXT,AAAA,-t TYPE64,-t TYPE65", ",") {
		_, err = exec.Command("bash", "-c", fmt.Sprintf("dig %v example.com @127.0.0.1 -p %v", x, port)).CombinedOutput()
		if err != nil {
			t.Error(err)
			return
		}
	}

	for _, x := range strings.Split("SOA,PTR", ",") {
		_, err = exec.Command("bash", "-c", fmt.Sprintf("dig %v 183.2.172.42 @127.0.0.1 -p %v", x, port)).CombinedOutput()
		if err != nil {
			t.Error(err)
			return
		}
	}

	ln.Close()

	{
		req := &dnsmessage.Message{
			Questions: []dnsmessage.Question{
				{
					Name:  dnsmessage.MustNewName("example.com."),
					Type:  dnsmessage.TypeSRV,
					Class: dnsmessage.ClassINET,
				},
			},
		}
		request, _ := req.Pack()
		_, err := resolver.Query(context.Background(), request)
		if err == nil {
			t.Error(err)
			return
		}
	}
	{
		req := &dnsmessage.Message{}
		request, _ := req.Pack()
		_, err := resolver.Query(context.Background(), request)
		if err == nil {
			t.Error(err)
			return
		}
	}
	{
		_, err := resolver.Query(context.Background(), []byte{})
		if err == nil {
			t.Error(err)
			return
		}
	}
}

func TestGateway(t *testing.T) {
	tester := xdebug.CaseTester{
		0: 1,
		4: 1,
	}
	if tester.Run("Piper") { //Piper
		gw := NewGateway(3)
		ln, err := net.ListenPacket("udp", "127.0.0.1:10453")
		if err != nil {
			t.Error(err)
			return
		}

		conn := NewConn(ln)
		go gw.PipeConn(conn, "dns://resolver")

		text, err := exec.Command("bash", "-c", "dig example.com @127.0.0.1 -p 10453").CombinedOutput()
		if err != nil {
			t.Error(err)
			return
		}
		fmt.Printf("result is %v\n", string(text))
		ln.Close()
		gw.Close()
	}
	if tester.Run("ReadWriterCloser") { //ReadWriterCloser
		gw := NewGateway(3)
		ln, err := net.ListenPacket("udp", "127.0.0.1:10453")
		if err != nil {
			t.Error(err)
			return
		}

		conn := NewConn(ln)
		go io.Copy(conn, gw)
		go io.Copy(gw, conn)

		text, err := exec.Command("bash", "-c", "dig baidu.com @127.0.0.1 -p 10453").CombinedOutput()
		if err != nil {
			t.Error(err)
			return
		}
		fmt.Printf("result is %v\n", string(text))
		ln.Close()

		conn.addrLast[100] = time.Now().Add(-time.Hour)
		conn.clearTimeoutLocked()
		gw.Close()
	}
	if tester.Run("CopyPiper") { // CopyPiper
		gw := NewGateway(3)
		ln, err := net.ListenPacket("udp", "127.0.0.1:10453")
		if err != nil {
			t.Error(err)
			return
		}

		conn := NewConn(ln)
		piper := xio.NewCopyPiper(gw, 2048)
		go func() {
			err := piper.PipeConn(conn, "tcp://dnspgw")
			fmt.Printf("--->%v\n", err)
		}()

		text, err := exec.Command("bash", "-c", "dig baidu.com @127.0.0.1 -p 10453").CombinedOutput()
		if err != nil {
			t.Error(err)
			return
		}
		fmt.Printf("result is %v\n", string(text))
		ln.Close()

		conn.addrLast[100] = time.Now().Add(-time.Hour)
		conn.clearTimeoutLocked()
		gw.Close()
	}
	if tester.Run("cover") { //cover
		gw := NewGateway(3)
		gw.Close()

		gw.procQuery(nil)
		gw.procQuery(&queryTask{request: []byte{1, 2, 3}})

		gw.queryTask = make(chan *queryTask, 1)
		gw.queryTask <- nil
		gw.recvData([]byte{1, 23}, nil)

		gw.readBuffer = make(chan []byte, 1)
		gw.readBuffer <- nil
		gw.sendData(nil)

		gw.Close()
		gw.Close()

		conn := NewConn(nil)
		conn.Write(nil)
		conn.Write([]byte{1, 2, 3, 4})
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
	{ //normal
		ln, err := net.ListenPacket("udp", "127.0.0.1:10453")
		if err != nil {
			t.Error(err)
			return
		}
		conn := NewConn(ln)
		var dialErr error
		dialer := xio.PiperDialerF(func(uri string, bufferSize int) (raw xio.Piper, err error) {
			raw = &forwardPiper{Piper: NewGateway(3)}
			err = dialErr
			return
		})
		forwarder := NewForwarder(dialer, 2048)
		forwarder.Cache = NewCache()
		forwarder.Policy = func(conid uint16, questions []string) string { return "*" }
		waiter := make(chan int, 1)
		go func() {
			forwarder.ServeConn(conn)
			waiter <- 1
		}()

		text, err := exec.Command("bash", "-c", "dig example.com @127.0.0.1 -p 10453").CombinedOutput()
		if err != nil {
			t.Error(err)
			return
		}
		fmt.Printf("result is %v\n", string(text))

		ln.Close()

		//cover
		forwarder.procData(nil, []byte{})
		forwarder.procData(nil, []byte{1, 2, 3})
		dialErr = fmt.Errorf("test error")
		testDAta := []byte{0, 1, 58, 73, 1, 32, 0, 1, 0, 0, 0, 0, 0, 1, 5, 98, 97, 105, 100, 117, 3, 99, 111, 109, 0, 0, 1, 0, 1, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0}
		forwarder.procData(conn, testDAta)

		fc := forwarderConn{}
		fc.send([]byte("xx"))
		fc.Close()
		fc.Close()

		<-waiter
	}
	time.Sleep(100 * time.Millisecond)
}
