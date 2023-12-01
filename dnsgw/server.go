package dnsproxy

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/codingeasygo/tun2conn/log"
	"github.com/codingeasygo/util/xdebug"
	"github.com/codingeasygo/util/xjson"
	"github.com/codingeasygo/util/xnet"
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
			c.CN[body.CNAME.String()] = answer.Header.Name.String()
		case dnsmessage.TypeA:
			body := answer.Body.(*dnsmessage.AResource)
			key := net.IP(body.A[:]).String()
			c.IP[key] = answer.Header.Name.String()
			c.Time[key] = now
		case dnsmessage.TypeAAAA:
			body := answer.Body.(*dnsmessage.AAAAResource)
			key := net.IP(body.AAAA[:]).String()
			c.IP[key] = answer.Header.Name.String()
			c.Time[key] = now
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
		return
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

type Conn struct {
	addr   string
	raw    io.ReadWriteCloser
	using  bool
	server *Server
	buffer []byte
	err    error
}

func (c *Conn) Query(request []byte) (response []byte, retry bool, err error) {
	_, err = c.raw.Write(request)
	if err != nil {
		c.err = err
		retry = true
		return
	}

	n, err := c.raw.Read(c.buffer)
	if err != nil {
		c.err = err
		retry = true
		return
	}
	response = make([]byte, n)
	copy(response, c.buffer[:n])
	return
}

func (c *Conn) Close() (err error) {
	if c.err != nil {
		c.server.RemoveConn(c)
		err = c.raw.Close()
	}
	c.using = false
	return
}

type requestTask struct {
	Conn    net.PacketConn
	From    net.Addr
	Request []byte
}

type Server struct {
	UpperAddr  map[string][]string
	MaxConn    int
	MaxTry     int
	Concurrent int
	Listen     string
	Dialer     xnet.Dialer
	Cache      *Cache
	Policy     func(request []byte) string
	connAll    map[string]map[string]map[string]*Conn
	connLock   sync.RWMutex
	taskQueue  chan *requestTask
	listener   *net.UDPConn
	exiter     chan int
	waiter     sync.WaitGroup
}

func NewServer() (server *Server) {
	server = &Server{
		UpperAddr: map[string][]string{
			"*": {"udp://8.8.4.4:53"},
		},
		MaxConn:    10,
		MaxTry:     3,
		Concurrent: 3,
		Dialer:     xnet.NewNetDailer(),
		connAll:    map[string]map[string]map[string]*Conn{},
		connLock:   sync.RWMutex{},
		taskQueue:  make(chan *requestTask, 32),
		exiter:     make(chan int, 10),
		waiter:     sync.WaitGroup{},
	}
	return
}

func (s *Server) AcquireConn(key string) (conn *Conn, err error) {
	s.connLock.Lock()
	defer s.connLock.Unlock()
	keyAll := s.connAll[key]
	if keyAll == nil {
		keyAll = map[string]map[string]*Conn{}
		s.connAll[key] = keyAll
	}
	for _, addr := range s.UpperAddr[key] {
		connAll := keyAll[addr]
		if connAll == nil {
			connAll = map[string]*Conn{}
			keyAll[addr] = connAll
		}
		for _, c := range connAll {
			if !c.using {
				c.using = true
				conn = c
				break
			}
		}
		if conn != nil {
			break
		}
	}
	if conn != nil {
		return
	}
	for _, addr := range s.UpperAddr[key] {
		connAll := keyAll[addr]
		if len(connAll) >= s.MaxConn {
			continue
		}
		raw, xerr := s.Dialer.Dial(addr)
		if xerr != nil {
			log.WarnLog("Server dial connect by %v error %v", addr, xerr)
			continue
		}
		conn = s.NewConn(addr, raw)
		connAll[fmt.Sprintf("%p", conn)] = conn
		break
	}
	if conn == nil {
		err = fmt.Errorf("conn is full or all error")
	}
	return
}

func (s *Server) RemoveConn(conn *Conn) {
	s.connLock.Lock()
	defer s.connLock.Unlock()
	conn.using = false
	delete(s.connAll[conn.addr], fmt.Sprintf("%p", conn))
}

func (s *Server) NewConn(addr string, raw io.ReadWriteCloser) (conn *Conn) {
	conn = &Conn{
		addr:   addr,
		raw:    raw,
		server: s,
		buffer: make([]byte, 1500),
	}
	return
}

func (s *Server) Query(request []byte) (response []byte, err error) {
	retry := true
	key := "*"
	if s.Policy != nil {
		key = s.Policy(request)
	}
	for i := 0; retry && i < s.MaxTry; i++ {
		conn, xerr := s.AcquireConn(key)
		if xerr != nil {
			err = xerr
			break
		}
		response, retry, err = conn.Query(request)
		conn.Close()
		if err == nil {
			break
		}
	}
	if s.Cache != nil && err == nil && len(response) > 0 {
		s.Cache.Add(response[:])
	}
	return
}

func (s *Server) procTask(task *requestTask) {
	defer func() {
		if perr := recover(); perr != nil {
			log.ErrorLog("Server proc task is panic with %v, callstack is \n%v", perr, xdebug.CallStack())
		}
	}()
	response, err := s.Query(task.Request)
	if err != nil {
		log.WarnLog("Server query error %v\n", err)
		return
	}
	task.Conn.WriteTo(response, task.From)
}

func (s *Server) loopTask() {
	defer s.waiter.Done()
	running := true
	for running {
		select {
		case <-s.exiter:
			running = false
		case task := <-s.taskQueue:
			s.procTask(task)
		}
	}
}

func (s *Server) addTask(conn net.PacketConn, from net.Addr, request []byte) {
	task := &requestTask{
		Conn:    conn,
		From:    from,
		Request: request,
	}
	select {
	case s.taskQueue <- task:
	default:
	}
}

func (s *Server) ServeConn(conn net.PacketConn) (err error) {
	for {
		buffer := make([]byte, 1500)
		n, from, xerr := conn.ReadFrom(buffer)
		if xerr != nil {
			err = xerr
			break
		}
		s.addTask(conn, from, buffer[:n])
	}
	return
}

func (s *Server) procListen(conn net.PacketConn) {
	defer s.waiter.Done()
	err := s.ServeConn(conn)
	log.InfoLog("Server listener on %v is stopped by %v", conn.LocalAddr(), err)
}

func (s *Server) Start() (err error) {
	if len(s.Listen) > 0 {
		addr, xerr := net.ResolveUDPAddr("udp", s.Listen)
		if xerr != nil {
			err = xerr
			return
		}
		ln, xerr := net.ListenUDP("udp", addr)
		if xerr != nil {
			err = xerr
			return
		}
		s.listener = ln
		s.waiter.Add(1)
		go s.procListen(s.listener)
	}
	for i := 0; i < s.Concurrent; i++ {
		s.waiter.Add(1)
		go s.loopTask()
	}
	return
}

func (s *Server) Stop() (err error) {
	if len(s.Listen) > 0 {
		s.exiter <- 1
		if s.listener != nil {
			s.listener.Close()
			s.listener = nil
		}
	}
	for i := 0; i < s.Concurrent; i++ {
		s.exiter <- 1
	}
	s.waiter.Wait()
	return
}
