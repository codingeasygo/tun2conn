package gfw

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestGFW(t *testing.T) {
	rules, err := ReadAllRules("gfwlist.txt", "user_rules.txt")
	if err != nil {
		t.Error(err)
		return
	}
	gfw := NewProxyGFW(rules...)
	gfw.Set(`
testproxy
192.168.1.18
	`, GfwProxy)
	if !gfw.IsProxy("youtube-ui.l.google.com") {
		t.Error("not proxy")
		return
	}
	if !gfw.IsProxy("google.com") {
		t.Error("not proxy")
		return
	}
	if !gfw.IsProxy("google.com.") {
		t.Error("not proxy")
		return
	}
	if !gfw.IsProxy(".google.com. ") {
		t.Error("not proxy")
		return
	}
	if !gfw.IsProxy("www.google.com.hk") {
		t.Error("not proxy")
		return
	}
	if !gfw.IsProxy("www.google.cn") {
		t.Error("not proxy")
		return
	}
	if !gfw.IsProxy("google.cn") {
		t.Error("not proxy")
		return
	}
	if !gfw.IsProxy(".youtube.com.") {
		t.Error("not proxy")
		return
	}
	if !gfw.IsProxy("testproxy") {
		t.Error("not proxy")
		return
	}
	if !gfw.IsProxy("d3c33hcgiwev3.cloudfront.net") {
		t.Error("not proxy")
		return
	}
	if !gfw.IsProxy("xx.wwwhost.biz") {
		t.Error("not proxy")
		return
	}
	if !gfw.IsProxy("www.ftchinese.com") {
		t.Error("not proxy")
		return
	}
	if gfw.IsProxy("xxddsf.com") {
		t.Error("hav proxy")
		return
	}
	if gfw.IsProxy("") {
		t.Error("hav proxy")
		return
	}
	if gfw.IsProxy("www.baidu.com") {
		t.Error("hav proxy")
		return
	}
	if gfw.IsProxy("baidu.com") {
		t.Error("hav proxy")
		return
	}
	if gfw.IsProxy("notexistxxx.com") {
		t.Error("hav proxy")
		return
	}
	if gfw.IsProxy("qq.com") {
		t.Error("hav proxy")
		return
	}
	if gfw.IsProxy("x.qq.com") {
		t.Error("hav proxy")
		return
	}
	if gfw.IsProxy("x1.x2.qq.com") {
		t.Error("hav proxy")
		return
	}
	if gfw.IsProxy("192.168.1.1") {
		t.Error("hav proxy")
		return
	}
	if !gfw.IsProxy("192.168.1.18") {
		t.Error("not proxy")
		return
	}
	fmt.Printf("info:%v\n", gfw)

	_, err = LoadGFW(".")
	if err != nil {
		t.Error(err)
		return
	}
	_, err = LoadGFW("none")
	if err != nil {
		t.Error(err)
		return
	}
	os.Remove("access")
	os.Mkdir("access", os.ModePerm)
	os.WriteFile("access/user_rules.txt", []byte("xxx"), 0100)
	_, err = LoadGFW("access")
	if err == nil {
		t.Error(err)
		return
	}
	os.WriteFile("access/gfwlist.txt", []byte("xxx"), 0100)
	_, err = LoadGFW("access")
	if err == nil {
		t.Error(err)
		return
	}
	os.RemoveAll("access")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/gfwlist.txt" {
			fmt.Fprintf(w, "%v", GfwlistDefault)
		} else {
			w.WriteHeader(404)
		}
	}))
	GfwlistSource = ts.URL + "/gfwlist.txt"
	err = UpdateGfwlist("/tmp/")
	if err != nil {
		t.Error(err)
		return
	}

	ReadGfwlist("abp.go")
	ReadGfwlist("none.txt")
	ReadUserRules("none.txt")

	DecodeAllRules("", "")

	CreateAbpJS(rules, "127.0.0.1:1000")
}
