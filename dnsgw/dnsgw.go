package dnsgw

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/codingeasygo/tun2conn/log"
	"github.com/codingeasygo/util/xdebug"
	"github.com/codingeasygo/util/xio"
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

type Querier interface {
	Query(ctx context.Context, request []byte) (response []byte, err error)
	Close() (err error)
}

type Dialer interface {
	DialQuerier(ctx context.Context, addr string) (querier Querier, err error)
}

type DialerF func(ctx context.Context, addr string) (querier Querier, err error)

func (d DialerF) DialQuerier(ctx context.Context, addr string) (querier Querier, err error) {
	return d(ctx, addr)
}

type netConn struct {
	net.Conn
}

func (n *netConn) Query(ctx context.Context, request []byte) (response []byte, err error) {
	dealine, ok := ctx.Deadline()
	if ok {
		n.Conn.SetDeadline(dealine)
	}
	_, err = n.Conn.Write(request)
	if err != nil {
		return
	}
	buffer := make([]byte, 2048)
	readed, err := n.Conn.Read(buffer)
	if err == nil {
		response = buffer[:readed]
	}
	return
}

type Resolver struct {
	R *net.Resolver
}

func NewResolver() (resolver *Resolver) {
	resolver = &Resolver{
		R: &net.Resolver{},
	}
	return
}

func (r *Resolver) Query(ctx context.Context, request []byte) (response []byte, err error) {
	var parser dnsmessage.Parser
	_, err = parser.Start(request)
	if err != nil {
		return
	}
	questions, _ := parser.AllQuestions()
	message := dnsmessage.Message{
		Header: dnsmessage.Header{Response: true, Authoritative: true},
	}
	found := false
	for _, question := range questions {
		switch question.Type {
		case dnsmessage.TypeCNAME:
			cname, _ := r.R.LookupCNAME(ctx, question.Name.String())
			if len(cname) > 0 {
				message.Answers = append(message.Answers, dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name:  question.Name,
						Type:  question.Type,
						Class: question.Class,
					},
					Body: &dnsmessage.CNAMEResource{
						CNAME: dnsmessage.MustNewName(cname),
					},
				})
				found = true
			}
		case dnsmessage.TypeA:
			ip, _ := r.R.LookupIP(ctx, "ip4", strings.TrimSuffix(question.Name.String(), "."))
			if len(ip) > 0 {
				message.Answers = append(message.Answers, dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name:  question.Name,
						Type:  question.Type,
						Class: question.Class,
					},
					Body: &dnsmessage.AResource{
						A: [4]byte(ip[0].To4()),
					},
				})
				found = true
			}
		case dnsmessage.TypeAAAA:
			ip, _ := r.R.LookupIP(ctx, "ip6", strings.TrimSuffix(question.Name.String(), "."))
			if len(ip) > 0 {
				message.Answers = append(message.Answers, dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name:  question.Name,
						Type:  question.Type,
						Class: question.Class,
					},
					Body: &dnsmessage.AAAAResource{
						AAAA: [16]byte(ip[0].To16()),
					},
				})
				found = true
			}
		}
	}
	if !found {
		err = fmt.Errorf("resolve fail")
		return
	}
	response, err = message.Pack()
	return
}

func (r *Resolver) Close() (err error) {
	return
}

type NetDialer net.Dialer

func NewNetDialer() (dialer *NetDialer) {
	dialer = &NetDialer{}
	return
}

func (n *NetDialer) DialQuerier(ctx context.Context, addr string) (querier Querier, err error) {
	addrURI, err := url.Parse(addr)
	if err != nil {
		return
	}
	raw, err := (*net.Dialer)(n).DialContext(ctx, addrURI.Scheme, addrURI.Host)
	if err == nil {
		querier = &netConn{Conn: raw}
	}
	return
}

type PiperConn struct {
	*xio.QueryConn
	addr   string
	piper  xio.Piper
	waiter sync.WaitGroup
}

func NewPiperConn(addr string, piper xio.Piper) (conn *PiperConn) {
	conn = &PiperConn{
		QueryConn: xio.NewQueryConn(),
		addr:      addr,
		piper:     piper,
		waiter:    sync.WaitGroup{},
	}
	conn.waiter.Add(1)
	go conn.pipeConn()
	return
}

func (p *PiperConn) pipeConn() {
	defer func() {
		if perr := recover(); perr != nil {
			log.ErrorLog("PiperDialer pipe conn is panic with %v, callstack is \n%v", perr, xdebug.CallStack())
		}
		p.waiter.Done()
	}()
	p.piper.PipeConn(p.QueryConn, p.addr)
}

func (p *PiperConn) Close() (err error) {
	p.QueryConn.Close()
	p.waiter.Wait()
	return
}

type PiperDialer struct {
	xio.PiperDialer
	BufferSize int
}

func NewPiperDialer(base xio.PiperDialer, bufferSize int) (dialer *PiperDialer) {
	dialer = &PiperDialer{
		PiperDialer: base,
		BufferSize:  bufferSize,
	}
	return
}

func (p *PiperDialer) DialQuerier(ctx context.Context, addr string) (querier Querier, err error) {
	raw, err := p.PiperDialer.DialPiper(addr, p.BufferSize)
	if err == nil {
		querier = NewPiperConn(addr, raw)
	}
	return
}

type Conn struct {
	Querier
	addr      string
	using     bool
	forwarder *Forwarder
	buffer    []byte
	err       error
}

func (c *Conn) Close() (err error) {
	if c.err != nil {
		c.forwarder.RemoveConn(c)
		err = c.Querier.Close()
	}
	c.using = false
	return
}

type requestTask struct {
	Conn    net.PacketConn
	From    net.Addr
	Request []byte
}

type Forwarder struct {
	UpperAddr  map[string][]string
	MaxConn    int
	MaxTry     int
	Concurrent int
	Listen     string
	Dialer     Dialer
	Cache      *Cache
	Policy     func(request []byte) string
	BufferSize int
	connAll    map[string]map[string]map[string]*Conn
	connLock   sync.RWMutex
	taskQueue  chan *requestTask
	listener   *net.UDPConn
	exiter     chan int
	waiter     sync.WaitGroup
}

func NewForwarder() (forwarder *Forwarder) {
	forwarder = &Forwarder{
		UpperAddr: map[string][]string{
			"*": {"udp://8.8.4.4:53"},
		},
		MaxConn:    10,
		MaxTry:     3,
		Concurrent: 3,
		Dialer:     NewNetDialer(),
		BufferSize: 2048,
		connAll:    map[string]map[string]map[string]*Conn{},
		connLock:   sync.RWMutex{},
		taskQueue:  make(chan *requestTask, 32),
		exiter:     make(chan int, 10),
		waiter:     sync.WaitGroup{},
	}
	return
}

func (f *Forwarder) AcquireConn(key string) (conn *Conn, err error) {
	f.connLock.Lock()
	defer f.connLock.Unlock()
	keyAll := f.connAll[key]
	if keyAll == nil {
		keyAll = map[string]map[string]*Conn{}
		f.connAll[key] = keyAll
	}
	for _, addr := range f.UpperAddr[key] {
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
	for _, addr := range f.UpperAddr[key] {
		connAll := keyAll[addr]
		if len(connAll) >= f.MaxConn {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		raw, xerr := f.Dialer.DialQuerier(ctx, addr)
		cancel()
		if xerr != nil {
			log.WarnLog("Server dial connect by %v error %v", addr, xerr)
			continue
		}
		conn = f.NewConn(addr, raw)
		connAll[fmt.Sprintf("%p", conn)] = conn
		break
	}
	if conn == nil {
		err = fmt.Errorf("conn is full or all error")
	}
	return
}

func (f *Forwarder) RemoveConn(conn *Conn) {
	f.connLock.Lock()
	defer f.connLock.Unlock()
	conn.using = false
	delete(f.connAll[conn.addr], fmt.Sprintf("%p", conn))
}

func (f *Forwarder) NewConn(addr string, raw Querier) (conn *Conn) {
	conn = &Conn{
		Querier:   raw,
		addr:      addr,
		forwarder: f,
		buffer:    make([]byte, 2048),
	}
	return
}

func (f *Forwarder) closeAllConn() {
	connAll := []*Conn{}
	f.connLock.RLock()
	for _, c1 := range f.connAll {
		for _, c2 := range c1 {
			for _, conn := range c2 {
				connAll = append(connAll, conn)
			}
		}
	}
	f.connLock.RUnlock()
	for _, conn := range connAll {
		conn.Close()
	}
}

func (f *Forwarder) Query(request []byte) (response []byte, err error) {
	key := "*"
	if f.Policy != nil {
		key = f.Policy(request)
	}
	for i := 0; i < f.MaxTry; i++ {
		conn, xerr := f.AcquireConn(key)
		if xerr != nil {
			err = xerr
			break
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		response, err = conn.Query(ctx, request)
		cancel()
		conn.Close()
		if err == nil {
			break
		}
	}
	if f.Cache != nil && err == nil && len(response) > 0 {
		f.Cache.Add(response[:])
	}
	return
}

func (f *Forwarder) procTask(task *requestTask) {
	defer func() {
		if perr := recover(); perr != nil {
			log.ErrorLog("Server proc task is panic with %v, callstack is \n%v", perr, xdebug.CallStack())
		}
	}()
	response, err := f.Query(task.Request)
	if err != nil {
		log.WarnLog("Server query error %v\n", err)
		return
	}
	task.Conn.WriteTo(response, task.From)
}

func (f *Forwarder) loopTask() {
	defer f.waiter.Done()
	running := true
	for running {
		select {
		case <-f.exiter:
			running = false
		case task := <-f.taskQueue:
			f.procTask(task)
		}
	}
}

func (f *Forwarder) addTask(conn net.PacketConn, from net.Addr, request []byte) {
	task := &requestTask{
		Conn:    conn,
		From:    from,
		Request: request,
	}
	select {
	case f.taskQueue <- task:
	default:
	}
}

func (f *Forwarder) ServeConn(conn net.PacketConn) (err error) {
	for {
		buffer := make([]byte, 1500)
		n, from, xerr := conn.ReadFrom(buffer)
		if xerr != nil {
			err = xerr
			log.InfoLog("Forwarder(%v) read is done by %v", conn, err)
			break
		}
		f.addTask(conn, from, buffer[:n])
	}
	return
}

func (f *Forwarder) procListen(conn net.PacketConn) {
	defer f.waiter.Done()
	err := f.ServeConn(conn)
	log.InfoLog("Server listener on %v is stopped by %v", conn.LocalAddr(), err)
}

func (f *Forwarder) Start() (err error) {
	if len(f.Listen) > 0 {
		addr, xerr := net.ResolveUDPAddr("udp", f.Listen)
		if xerr != nil {
			err = xerr
			return
		}
		ln, xerr := net.ListenUDP("udp", addr)
		if xerr != nil {
			err = xerr
			return
		}
		f.listener = ln
		f.waiter.Add(1)
		go f.procListen(f.listener)
	}
	for i := 0; i < f.Concurrent; i++ {
		f.waiter.Add(1)
		go f.loopTask()
	}
	return
}

func (f *Forwarder) Stop() (err error) {
	f.closeAllConn()
	if len(f.Listen) > 0 {
		f.exiter <- 1
		if f.listener != nil {
			f.listener.Close()
			f.listener = nil
		}
	}
	for i := 0; i < f.Concurrent; i++ {
		f.exiter <- 1
	}
	f.waiter.Wait()
	return
}
