package gfw

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/codingeasygo/util/xhttp"
)

const (
	//GfwProxy is GFW target for proxy
	GfwProxy = "proxy"
	//GfwLocal is GFW target for local
	GfwLocal = "local"
)

var GfwlistSource = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"

// GFW impl check if domain in gfw list
type GFW struct {
	list map[string]string
	lck  sync.RWMutex
}

// NewGFW will create new GFWList
func NewGFW() (gfw *GFW) {
	gfw = &GFW{
		list: map[string]string{
			"*": GfwLocal,
		},
		lck: sync.RWMutex{},
	}
	return
}

func NewProxyGFW(rules ...string) (gfw *GFW) {
	gfw = NewGFW()
	gfw.Set(strings.Join(rules, "\n"), GfwProxy)
	return
}

// Set list
func (g *GFW) Set(list, target string) {
	g.lck.Lock()
	defer g.lck.Unlock()
	g.list[list] = target
}

func (g *GFW) Clear() {
	g.lck.Lock()
	defer g.lck.Unlock()
	g.list = map[string]string{}
}

// IsProxy return true, if domain target is dns://proxy
func (g *GFW) IsProxy(domain string) bool {
	return g.Find(domain) == GfwProxy
}

// Find domain target
func (g *GFW) Find(domain string) (target string) {
	g.lck.RLock()
	defer g.lck.RUnlock()
	domain = strings.Trim(domain, " \t.")
	if len(domain) < 1 {
		target = g.list["*"]
		return
	}
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		target = g.check(parts...)
	} else {
		n := len(parts) - 1
		for i := 0; i < n; i++ {
			target = g.check(parts[i:]...)
			if len(target) > 0 {
				break
			}
		}
	}
	if len(target) < 1 {
		target = g.list["*"]
	}
	return
}

func (g *GFW) check(parts ...string) (target string) {
	ptxt := fmt.Sprintf("(?m)^[^\\@]*[\\|\\.]*(http://)?(https://)?%v$", strings.Join(parts, "\\."))
	pattern, err := regexp.Compile(ptxt)
	if err == nil {
		for key, val := range g.list {
			if len(pattern.FindString(key)) > 0 {
				target = val
				break
			}
		}
	}
	return
}

func (g *GFW) String() string {
	return "GFW"
}

// ReadGfwlist will read and decode gfwlist file
func ReadGfwlist(gfwFile string) (rules []string, err error) {
	gfwRaw, err := os.ReadFile(gfwFile)
	if err != nil {
		return
	}
	rules, err = DecodeGfwlist(string(gfwRaw))
	return
}

// DecodeGfwlist will read and decode gfwlist file
func DecodeGfwlist(gfwRaw string) (rules []string, err error) {
	gfwData, err := base64.StdEncoding.DecodeString(gfwRaw)
	if err != nil {
		err = fmt.Errorf("decode gfwlist.txt fail with %v", err)
		return
	}
	gfwRulesAll := strings.Split(string(gfwData), "\n")
	for _, rule := range gfwRulesAll {
		if strings.HasPrefix(rule, "[") || strings.HasPrefix(rule, "!") || len(strings.TrimSpace(rule)) < 1 {
			continue
		}
		rules = append(rules, rule)
	}
	return
}

// ReadUserRules will read and decode user rules
func ReadUserRules(gfwFile string) (rules []string, err error) {
	gfwData, err := os.ReadFile(gfwFile)
	if err != nil {
		return
	}
	rules = DecodeUserRules(string(gfwData))
	return
}

func DecodeUserRules(gfwData string) (rules []string) {
	gfwRulesAll := strings.Split(gfwData, "\n")
	for _, rule := range gfwRulesAll {
		rule = strings.TrimSpace(rule)
		if strings.HasPrefix(rule, "--") || strings.HasPrefix(rule, "!") || len(strings.TrimSpace(rule)) < 1 {
			continue
		}
		rules = append(rules, rule)
	}
	return
}

func ReadAllRules(gfwFile, userFile string) (rules []string, err error) {
	rules, err = ReadGfwlist(gfwFile)
	if err == nil {
		userRules, _ := ReadUserRules(userFile)
		rules = append(rules, userRules...)
	}
	return
}

func DecodeAllRules(gfwData, userData string) (rules []string, err error) {
	rules, err = DecodeGfwlist(gfwData)
	if err == nil {
		rules = append(rules, DecodeUserRules(userData)...)
	}
	return
}

func CreateAbpJS(gfwRules []string, proxyAddr string) (js string) {
	gfwRulesJS, _ := json.Marshal(gfwRules)
	parts := strings.Split(proxyAddr, ":")
	js = strings.Replace(ABP_JS, "__RULES__", string(gfwRulesJS), 1)
	js = strings.Replace(js, "__SOCKS5ADDR__", strings.Join(parts[:len(parts)-1], ":"), -1)
	js = strings.Replace(js, "__SOCKS5PORT__", parts[len(parts)-1], -1)
	return
}

type Cache struct {
	Dir       string
	Gfwlist   string
	UserRules string
	gfw       *GFW
}

func NewCache(dir string) (cache *Cache) {
	cache = &Cache{
		Dir:       dir,
		Gfwlist:   "gfwlist.txt",
		UserRules: "user_rules.txt",
	}
	return
}

func (c *Cache) Reset() (err error) {
	rules, err := c.LoadAllRules()
	if err != nil {
		return
	}
	if c.gfw == nil {
		c.gfw = NewGFW()
	}
	c.gfw.Clear()
	c.gfw.Set(strings.Join(rules, "\n"), GfwProxy)
	return
}

func (c *Cache) LoadAllRules() (rules []string, err error) {
	if len(c.Gfwlist) > 0 {
		var gfwRules []string
		if strings.HasSuffix(c.Gfwlist, ".txt") {
			gfwRules, err = ReadGfwlist(filepath.Join(c.Dir, c.Gfwlist))
		} else {
			gfwRules, err = DecodeGfwlist(c.Gfwlist)
		}
		if os.IsNotExist(err) {
			rules, err = DecodeGfwlist(GfwlistDefault)
		}
		if err != nil {
			return
		}
		rules = append(rules, gfwRules...)
	}
	if len(c.UserRules) > 0 {
		var userRules []string
		if strings.HasSuffix(c.UserRules, ".txt") {
			userRules, err = ReadUserRules(filepath.Join(c.Dir, c.UserRules))
		} else {
			userRules = DecodeUserRules(c.Gfwlist)
		}
		if os.IsNotExist(err) {
			err = nil
		}
		if err != nil {
			return
		}
		rules = append(rules, userRules...)
	}
	return
}

func (c *Cache) Update(client *xhttp.Client, source string) (err error) {
	if len(source) < 1 {
		source = GfwlistSource
	}
	gfwRules, err := client.GetBytes("%v", source)
	if err != nil {
		return
	}
	if strings.HasSuffix(c.Gfwlist, ".txt") {
		err = os.WriteFile(filepath.Join(c.Dir, c.Gfwlist), gfwRules, os.ModePerm)
	} else {
		c.Gfwlist = string(gfwRules)
	}
	if err == nil {
		c.Reset()
	}
	return
}

func (c *Cache) LoadGFW() (gfw *GFW, err error) {
	if gfw == nil {
		err = c.Reset()
	}
	gfw = c.gfw
	return
}

func (c *Cache) CreateAbpJS(proxyAddr string) (js string, err error) {
	rules, err := c.LoadAllRules()
	if err == nil {
		js = CreateAbpJS(rules, proxyAddr)
	}
	return
}
