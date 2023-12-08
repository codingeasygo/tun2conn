package dnsgw

import (
	"context"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/codingeasygo/util/xio"
	"golang.org/x/net/dns/dnsmessage"
)

func init() {
	go http.ListenAndServe(":6063", nil)
}

func TestCache(t *testing.T) {
	defer os.Remove("cache.json")
	cache := NewCache()
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
	cache.Add(pack)
	cache.Add([]byte{})

	domain, cname, _ := cache.Reflect("127.0.0.1")
	if domain != "a.example.com." || cname != "example.com." {
		t.Error("error")
		return
	}

	err = cache.Store("cache.json")
	if err != nil {
		t.Error(err)
		return
	}

	cache2 := NewCache()
	err = cache2.Resume("cache.json")
	if err != nil {
		t.Error(err)
		return
	}
	domain, cname, _ = cache2.Reflect("127.0.0.1")
	if domain != "a.example.com." || cname != "example.com." {
		t.Error("error")
		return
	}
	cache2.UpdateTime()

	cache2.Timeout(time.Minute)
	cache2.Timeout(0)

	//
	cache.SaveDelay = 100 * time.Millisecond
	cache.SaveFile = "cache.json"
	err = cache.Start()
	if err != nil {
		t.Error(err)
		return
	}
	time.Sleep(100 * time.Millisecond)
	cache.Stop()

	//start error
	os.WriteFile("cache.json", []byte("xxxx"), os.ModePerm)
	cache3 := NewCache()
	cache3.SaveFile = "cache.json"
	err = cache3.Start()
	if err == nil {
		t.Error(err)
		return
	}

	cache3 = NewCache()
	cache3.SaveFile = "none/cache.json"
	cache3.SaveDelay = 100 * time.Millisecond
	cache3.Update++
	cache3.waiter.Add(1)
	go cache3.loopStore()
	time.Sleep(200 * time.Millisecond)
	cache3.exiter <- 1
}

type ErrRWC struct {
	ReadErr  error
	WriteErr error
}

func (e *ErrRWC) Read(p []byte) (n int, err error) {
	err = e.ReadErr
	return
}

func (e *ErrRWC) Write(p []byte) (n int, err error) {
	err = e.WriteErr
	return
}

func (e *ErrRWC) Close() (err error) {
	return
}

func TestNetDialer(t *testing.T) {
	udpServer, _ := net.ListenUDP("udp", nil)
	go func() {
		buffer := make([]byte, 1024)
		for {
			n, from, err := udpServer.ReadFrom(buffer)
			if err != nil {
				break
			}
			udpServer.WriteTo(buffer[:n], from)
		}
	}()
	dialer := NewNetDialer()
	_, err := dialer.DialQuerier(context.Background(), "udp://xxx:xx")
	if err == nil {
		t.Error(err)
		return
	}
	querier, err := dialer.DialQuerier(context.Background(), fmt.Sprintf("udp://127.0.0.1:%v", udpServer.LocalAddr().(*net.UDPAddr).Port))
	if err != nil {
		t.Error(err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	_, err = querier.Query(ctx, []byte("abc"))
	cancel()
	if err != nil {
		t.Error(err)
		return
	}
	querier.Close()
	_, err = querier.Query(context.Background(), []byte("abc"))
	if err == nil {
		t.Error(err)
		return
	}
}

func TestPiperDialer(t *testing.T) {
	dialer := NewPiperDialer(xio.PiperDialerF(xio.DialNetPiper), 1024)
	querier, err := dialer.DialQuerier(context.Background(), "udp://192.168.1.1:53")
	if err != nil {
		t.Error(err)
		return
	}
	querier.Close()

	pc := &PiperConn{
		waiter: sync.WaitGroup{},
	}
	pc.waiter.Add(1)
	pc.pipeConn()
}

func TestForwarder(t *testing.T) {
	defer os.Remove("cache.json")
	forwarder := NewForwarder()
	forwarder.UpperAddr["*"] = []string{"udp://192.168.1.1:53"}
	forwarder.MaxConn = 1
	forwarder.Policy = func(request []byte) string { return "*" }
	forwarder.Listen = ":10253"
	forwarder.Cache = NewCache()
	msg := dnsmessage.Message{
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName("www.baidu.com."),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	pack, _ := msg.Pack()

	_, err := forwarder.Query(pack)
	if err != nil {
		t.Error(err)
		return
	}
	response, err := forwarder.Query(pack)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Printf("--->%v\n", response)

	//listen
	err = forwarder.Start()
	if err != nil {
		t.Error(err)
		return
	}
	conn, err := net.Dial("udp", "127.0.0.1:10253")
	if err != nil {
		t.Error(err)
		return
	}
	conn.Write(pack)
	buffer := make([]byte, 1500)
	conn.Read(buffer)
	conn.Close()

	forwarder.Stop()

	//acquire
	conn1, err := forwarder.AcquireConn("*")
	if err != nil {
		t.Error(err)
		return
	}
	_, err = forwarder.AcquireConn("*")
	if err == nil {
		t.Error(err)
		return
	}
	conn1.err = fmt.Errorf("error")
	conn1.Close()

	//dialer error
	forwarder = NewForwarder()
	forwarder.Dialer = DialerF(func(ctx context.Context, addr string) (querier Querier, err error) {
		return nil, fmt.Errorf("error")
	})
	_, err = forwarder.Query(pack)
	if err == nil {
		t.Error(err)
		return
	}

	// //connect error
	// errConn := &ErrRWC{}
	// conn2 := forwarder.NewConn("test", errConn)

	// errConn.ReadErr = fmt.Errorf("error")
	// _, _, err = conn2.Query(pack)
	// if err == nil {
	// 	t.Error(err)
	// 	return
	// }
	// errConn.WriteErr = fmt.Errorf("error")
	// _, _, err = conn2.Query(pack)
	// if err == nil {
	// 	t.Error(err)
	// 	return
	// }

	//listen error
	forwarder = NewForwarder()
	forwarder.Listen = ":xxs"
	err = forwarder.Start()
	if err == nil {
		t.Error(err)
		return
	}
	forwarder.Listen = ":10253"
	err = forwarder.Start()
	if err != nil {
		t.Error(err)
		return
	}
	err = forwarder.Start()
	if err == nil {
		t.Error(err)
		return
	}
	forwarder.Stop()

	//task error
	forwarder = NewForwarder()
	forwarder.UpperAddr["*"] = []string{"udp://192.168.1.1:53"}

	forwarder.procTask(&requestTask{Request: pack})

	forwarder = NewForwarder()
	forwarder.UpperAddr["*"] = []string{"udp://192.168.1.1:53"}
	forwarder.Dialer = DialerF(func(ctx context.Context, addr string) (querier Querier, err error) {
		return nil, fmt.Errorf("error")
	})
	forwarder.procTask(&requestTask{})

	forwarder.taskQueue = make(chan *requestTask, 1)
	forwarder.taskQueue <- nil
	forwarder.addTask(nil, nil, nil)
}

func TestResolver(t *testing.T) {
	resolver := NewResolver()
	{
		req := &dnsmessage.Message{
			Questions: []dnsmessage.Question{
				{
					Name:  dnsmessage.MustNewName("example.com."),
					Type:  dnsmessage.TypeCNAME,
					Class: dnsmessage.ClassINET,
				},
				{
					Name:  dnsmessage.MustNewName("example.com."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				},
				{
					Name:  dnsmessage.MustNewName("example.com."),
					Type:  dnsmessage.TypeAAAA,
					Class: dnsmessage.ClassINET,
				},
			},
		}
		request, _ := req.Pack()
		_, err := resolver.Query(context.Background(), request)
		if err != nil {
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
	resolver.Close()
}
