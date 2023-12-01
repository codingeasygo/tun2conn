package dnsproxy

import (
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"testing"
	"time"

	"github.com/codingeasygo/util/xnet"
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

func TestServer(t *testing.T) {
	defer os.Remove("cache.json")
	server := NewServer()
	server.UpperAddr["*"] = []string{"udp://192.168.1.1:53"}
	server.MaxConn = 1
	server.Policy = func(request []byte) string { return "*" }
	server.Listen = ":10253"
	server.Cache = NewCache()
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

	_, err := server.Query(pack)
	if err != nil {
		t.Error(err)
		return
	}
	response, err := server.Query(pack)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Printf("--->%v\n", response)

	//listen
	err = server.Start()
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

	server.Stop()

	//acquire
	conn1, err := server.AcquireConn("*")
	if err != nil {
		t.Error(err)
		return
	}
	_, err = server.AcquireConn("*")
	if err == nil {
		t.Error(err)
		return
	}
	conn1.err = fmt.Errorf("error")
	conn1.Close()

	//dialer error
	server = NewServer()
	server.Dialer = xnet.NewRawDialerWrapper(xnet.RawDialerF(func(network, address string) (net.Conn, error) {
		return nil, fmt.Errorf("error")
	}))
	_, err = server.Query(pack)
	if err == nil {
		t.Error(err)
		return
	}

	//connect error
	errConn := &ErrRWC{}
	conn2 := server.NewConn("test", errConn)

	errConn.ReadErr = fmt.Errorf("error")
	_, _, err = conn2.Query(pack)
	if err == nil {
		t.Error(err)
		return
	}
	errConn.WriteErr = fmt.Errorf("error")
	_, _, err = conn2.Query(pack)
	if err == nil {
		t.Error(err)
		return
	}

	//listen error
	server = NewServer()
	server.Listen = ":xxs"
	err = server.Start()
	if err == nil {
		t.Error(err)
		return
	}
	server.Listen = ":10253"
	err = server.Start()
	if err != nil {
		t.Error(err)
		return
	}
	err = server.Start()
	if err == nil {
		t.Error(err)
		return
	}
	server.Stop()

	//task error
	server = NewServer()
	server.UpperAddr["*"] = []string{"udp://192.168.1.1:53"}

	server.procTask(&requestTask{Request: pack})

	server = NewServer()
	server.UpperAddr["*"] = []string{"udp://192.168.1.1:53"}
	server.Dialer = xnet.NewRawDialerWrapper(xnet.RawDialerF(func(network, address string) (net.Conn, error) {
		return nil, fmt.Errorf("error")
	}))
	server.procTask(&requestTask{})

	server.taskQueue = make(chan *requestTask, 1)
	server.taskQueue <- nil
	server.addTask(nil, nil, nil)
}
