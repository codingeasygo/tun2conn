package dnsgw

import (
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/codingeasygo/tun2conn/log"
	"github.com/codingeasygo/util/xjson"
	"github.com/codingeasygo/util/xtime"
	"golang.org/x/net/dns/dnsmessage"
)

type cacheData struct {
	CN     map[string]string `json:"cn"`
	IP     map[string]string `json:"ip"`
	Time   map[string]int64  `json:"time"`
	Update int64             `json:"update"`
}

type Cache struct {
	MaxAlive  time.Duration
	SaveDelay time.Duration
	SaveFile  string
	cacheData
	lock   sync.RWMutex
	exiter chan int
	waiter sync.WaitGroup
}

func NewCache() (cache *Cache) {
	cache = &Cache{
		MaxAlive:  24 * time.Hour,
		SaveDelay: 10 * time.Second,
		cacheData: cacheData{
			CN:   map[string]string{},
			IP:   map[string]string{},
			Time: map[string]int64{},
		},
		lock:   sync.RWMutex{},
		exiter: make(chan int, 1),
		waiter: sync.WaitGroup{},
	}
	return
}

func (c *Cache) Add(response []byte) {
	c.lock.Lock()
	defer c.lock.Unlock()
	var parser dnsmessage.Parser
	_, err := parser.Start(response)
	if err != nil {
		log.WarnLog("Cache parse response error %v", err)
		return
	}
	parser.SkipAllQuestions()
	answers, _ := parser.AllAnswers()
	for _, answer := range answers {
		now := xtime.Now()
		switch answer.Header.Type {
		case dnsmessage.TypeCNAME:
			body := answer.Body.(*dnsmessage.CNAMEResource)
			domain := strings.TrimSuffix(answer.Header.Name.String(), ".")
			c.CN[body.CNAME.String()] = domain
			log.DebugLog("Cache add CNAME record by %v=>%v", body.CNAME, domain)
		case dnsmessage.TypeA:
			body := answer.Body.(*dnsmessage.AResource)
			key := net.IP(body.A[:]).String()
			domain := strings.TrimSuffix(answer.Header.Name.String(), ".")
			c.IP[key] = domain
			c.Time[key] = now
			log.DebugLog("Cache add A record by %v=>%v", key, domain)
		case dnsmessage.TypeAAAA:
			body := answer.Body.(*dnsmessage.AAAAResource)
			key := net.IP(body.AAAA[:]).String()
			domain := strings.TrimSuffix(answer.Header.Name.String(), ".")
			c.IP[key] = domain
			c.Time[key] = now
			log.DebugLog("Cache add AAAA record by %v=>%v", key, domain)
		}
		c.Update = now
	}
}

func (c *Cache) Reflect(ip string) (domain, cname string, update int64) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	domain = c.IP[ip]
	cname = c.CN[domain]
	update = c.Time[ip]
	return
}

func (c *Cache) Store(filename string) (err error) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	err = xjson.WriteJSONFile(filename, c.cacheData)
	return
}

func (c *Cache) Resume(filename string) (err error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	err = xjson.ReadSONFile(filename, &c.cacheData)
	return
}

func (c *Cache) UpdateTime() (update int64) {
	update = c.Update
	return
}

func (c *Cache) Timeout(max time.Duration) {
	c.lock.Lock()
	defer c.lock.Unlock()
	now := xtime.Now()
	maxMS := max.Milliseconds()
	for ip, ut := range c.Time {
		if now-ut < maxMS {
			continue
		}
		domain := c.IP[ip]
		delete(c.IP, ip)
		delete(c.CN, domain)
	}
}

func (c *Cache) loopStore() {
	defer c.waiter.Done()
	log.InfoLog("Cache store task to %v by %v", c.SaveFile, c.SaveDelay)
	ticker := time.NewTicker(c.SaveDelay)
	lastUpdate := int64(0)
	running := true
	for running {
		select {
		case <-c.exiter:
			running = false
		case <-ticker.C:
			if c.Update != lastUpdate {
				c.Timeout(c.MaxAlive)
				err := c.Store(c.SaveFile)
				if err != nil {
					log.ErrorLog("Cache store cache to %v error %v", c.SaveFile, err)
				}
				lastUpdate = c.Update
			}
		}
	}
	log.InfoLog("Cache store task to %v is stopped", c.SaveFile)
}

func (c *Cache) Start() (err error) {
	err = c.Resume(c.SaveFile)
	if err != nil && !os.IsNotExist(err) {
		log.WarnLog("Cache resume from %v fail with %v", c.SaveFile, err)
	}
	err = nil
	c.waiter.Add(1)
	go c.loopStore()
	return
}

func (c *Cache) Stop() {
	c.exiter <- 1
	c.waiter.Wait()
}
