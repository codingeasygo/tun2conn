package dnsgw

import (
	"os"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

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
	cache3.Start()

	cache3 = NewCache()
	cache3.SaveFile = "none/cache.json"
	cache3.SaveDelay = 100 * time.Millisecond
	cache3.Update++
	cache3.waiter.Add(1)
	go cache3.loopStore()
	time.Sleep(200 * time.Millisecond)
	cache3.exiter <- 1
}
