package dnsgw

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/codingeasygo/tun2conn/log"
	"github.com/codingeasygo/util/xdebug"
	"github.com/codingeasygo/util/xio"
	"golang.org/x/net/dns/dnsmessage"
)

type Resolver net.Resolver

func (r *Resolver) Query(ctx context.Context, request []byte) (response []byte, err error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(request)
	if err != nil {
		return
	}
	questions, _ := parser.AllQuestions()
	message := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:            header.ID,
			Response:      true,
			Authoritative: true,
		},
	}
	found := false
	for _, question := range questions {
		switch question.Type {
		case dnsmessage.TypeCNAME:
			cname, _ := (*net.Resolver)(r).LookupCNAME(ctx, question.Name.String())
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
			ip, _ := (*net.Resolver)(r).LookupIP(ctx, "ip4", strings.TrimSuffix(question.Name.String(), "."))
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
			ip, _ := (*net.Resolver)(r).LookupIP(ctx, "ip6", strings.TrimSuffix(question.Name.String(), "."))
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
	} else {
		response, err = message.Pack()
	}
	return
}

type queryTask struct {
	request []byte
	write   func([]byte) (int, error)
}

type Gateway struct {
	MTU        int
	Timeout    time.Duration
	runner     int
	resolver   *Resolver
	readBuffer chan []byte //buffer to read
	queryTask  chan *queryTask
	waiter     sync.WaitGroup
}

func NewGateway(runner int) (gw *Gateway) {
	gw = &Gateway{
		MTU:        2048,
		Timeout:    5 * time.Second,
		runner:     runner,
		resolver:   &Resolver{},
		readBuffer: make(chan []byte, runner*2),
		queryTask:  make(chan *queryTask, runner*2),
		waiter:     sync.WaitGroup{},
	}
	for i := 0; i < runner; i++ {
		gw.waiter.Add(1)
		go gw.loopQuery()
	}
	return
}

func (g *Gateway) String() string {
	return fmt.Sprintf("Gateway(dns/%v)", g.runner)
}

func (g *Gateway) loopQuery() {
	defer g.waiter.Done()
	for {
		task := <-g.queryTask
		if task == nil {
			break
		}
		g.procQuery(task)
	}
}

func (g *Gateway) procQuery(task *queryTask) {
	defer func() {
		if perr := recover(); perr != nil {
			log.ErrorLog("%v proc query is panic with %v, callstack is \n%v", g, perr, xdebug.CallStack())
		}
	}()
	ctx, cancle := context.WithTimeout(context.Background(), g.Timeout)
	response, err := g.resolver.Query(ctx, task.request[2:])
	cancle()
	if err != nil {
		return
	}
	data := make([]byte, len(response)+2)
	copy(data[0:2], task.request[0:2])
	copy(data[2:], response)
	task.write(data)
}

func (g *Gateway) recvData(request []byte, write func([]byte) (int, error)) {
	task := &queryTask{request: request, write: write}
	select {
	case g.queryTask <- task:
	default:
	}
}

func (g *Gateway) sendData(data []byte) (n int, err error) {
	select {
	case g.readBuffer <- data:
	default:
	}
	return len(data), nil
}

func (g *Gateway) PipeConn(conn io.ReadWriteCloser, target string) (err error) {
	defer func() {
		conn.Close()
		log.InfoLog("%v one connection %v is stopped by %v", g, conn, err)
	}()
	log.InfoLog("%v one connection %v is starting", g, conn)
	for {
		buffer := make([]byte, g.MTU)
		n, xerr := conn.Read(buffer)
		if xerr != nil {
			err = xerr
			break
		}
		g.recvData(buffer[:n], conn.Write)
	}
	return
}

func (g *Gateway) Write(p []byte) (n int, err error) {
	request := make([]byte, len(p))
	copy(request, p)
	g.recvData(request, g.sendData)
	return
}

func (g *Gateway) Read(p []byte) (n int, err error) {
	data := <-g.readBuffer
	if len(data) < 1 {
		err = fmt.Errorf("closed")
		return
	}
	n = copy(p, data)
	return
}

func (g *Gateway) Close() (err error) {
	for i := 0; i < g.runner; i++ {
		select {
		case g.queryTask <- nil:
		default:
		}
	}
	select {
	case g.readBuffer <- nil:
	default:
	}
	g.waiter.Wait()
	return
}

type Conn struct {
	MaxAlive time.Duration
	raw      net.PacketConn
	sequence uint16
	addrAll  map[uint16]net.Addr
	addrLast map[uint16]time.Time
	lock     sync.RWMutex
}

func NewConn(raw net.PacketConn) (conn *Conn) {
	conn = &Conn{
		MaxAlive: time.Minute,
		raw:      raw,
		addrAll:  map[uint16]net.Addr{},
		addrLast: map[uint16]time.Time{},
		lock:     sync.RWMutex{},
	}
	return
}

func (c *Conn) clearTimeoutLocked() {
	now := time.Now()
	for id, last := range c.addrLast {
		if now.Sub(last) > c.MaxAlive {
			delete(c.addrAll, id)
			delete(c.addrLast, id)
		}
	}
}

func (c *Conn) Read(p []byte) (n int, err error) {
	n, fromAddr, err := c.raw.ReadFrom(p[2:])
	if err != nil {
		return
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	c.clearTimeoutLocked()
	c.sequence++
	id := c.sequence
	binary.BigEndian.PutUint16(p[0:], id)
	c.addrAll[id] = fromAddr
	c.addrLast[id] = time.Now()
	n += 2
	return
}

func (c *Conn) Write(p []byte) (n int, err error) {
	if len(p) < 2 {
		err = fmt.Errorf("data error")
		return
	}
	conid := binary.BigEndian.Uint16(p[0:])
	data := p[2:]
	c.lock.RLock()
	fromAddr := c.addrAll[conid]
	c.lock.RUnlock()
	if fromAddr == nil { //ignore
		n = len(p)
		return
	}
	_, err = c.raw.WriteTo(data, fromAddr)
	n = len(p)
	return
}

func (c *Conn) Close() (err error) {
	err = c.raw.Close()
	return
}

func (c *Conn) String() string {
	return fmt.Sprintf("Conn(%v)", c.raw)
}

type forwarderConn struct {
	owner      *Forwarder
	readBuffer chan []byte
	base       *Conn
}

func newForwarderConn(owner *Forwarder, base *Conn) (conn *forwarderConn) {
	conn = &forwarderConn{
		owner:      owner,
		readBuffer: make(chan []byte, 3),
		base:       base,
	}
	return
}

func (c *forwarderConn) Read(p []byte) (n int, err error) {
	data := <-c.readBuffer
	if len(data) < 1 {
		err = fmt.Errorf("closed")
		return
	}
	n = copy(p, data)
	return
}

func (c *forwarderConn) send(data []byte) {
	buf := make([]byte, len(data))
	copy(buf, data)
	select {
	case c.readBuffer <- buf:
	default:
	}
}

func (c *forwarderConn) Write(p []byte) (n int, err error) {
	n, err = c.base.Write(p)
	if c.owner != nil && c.owner.Cache != nil {
		c.owner.Cache.Add(p[2:])
	}
	return
}

func (c *forwarderConn) Close() (err error) {
	c.readBuffer <- nil
	return
}

type Forwarder struct {
	Policy     func(id uint16, questions []string) string
	Cache      *Cache
	dialer     xio.PiperDialer
	bufferSize int
	nextAll    map[string]*forwarderConn
	nextLock   sync.RWMutex
	waiter     sync.WaitGroup
}

func NewForwarder(dialer xio.PiperDialer, bufferSize int) (forwarder *Forwarder) {
	forwarder = &Forwarder{
		dialer:     dialer,
		bufferSize: bufferSize,
		nextAll:    map[string]*forwarderConn{},
		nextLock:   sync.RWMutex{},
		waiter:     sync.WaitGroup{},
	}
	return
}

func (f *Forwarder) ServeConn(conn *Conn) {
	buffer := make([]byte, f.bufferSize)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			log.InfoLog("Forwarder(%v) read is done by %v", conn, err)
			break
		}
		f.procData(conn, buffer[:n])
	}
	for _, next := range f.nextAll {
		next.Close()
	}
	f.nextAll = map[string]*forwarderConn{}
	f.waiter.Wait()
}

func (f *Forwarder) procData(conn *Conn, buffer []byte) {
	defer func() {
		if perr := recover(); perr != nil {
			log.ErrorLog("Forward(%v) proc data is panic with %v, callstack is \n%v", conn, perr, xdebug.CallStack())
		}
	}()
	key := "*"
	if f.Policy != nil {
		var parser dnsmessage.Parser
		_, err := parser.Start(buffer[2:])
		if err != nil {
			log.WarnLog("Forward(%v) parse dns message fail with %v", conn, err)
			return
		}
		questions := []string{}
		qs, _ := parser.AllQuestions()
		for _, q := range qs {
			questions = append(questions, q.Name.String())
		}
		conid := binary.BigEndian.Uint16(buffer[0:])
		key = f.Policy(conid, questions)
	}
	f.nextLock.RLock()
	next := f.nextAll[key]
	f.nextLock.RUnlock()
	if next == nil {
		piper, err := f.dialer.DialPiper(key, f.bufferSize)
		if err != nil {
			log.WarnLog("Forwarder(%v) %v dialer dial piper by %v fail with %v", conn, key, key, err)
			return
		}
		next = newForwarderConn(f, conn)
		f.nextLock.Lock()
		f.nextAll[key] = next
		f.nextLock.Unlock()
		f.waiter.Add(1)
		go f.procPipe(piper, next, key)
	}
	next.send(buffer)
}

func (f *Forwarder) procPipe(piper xio.Piper, next *forwarderConn, key string) {
	defer func() {
		f.waiter.Done()
		f.nextLock.Lock()
		delete(f.nextAll, key)
		f.nextLock.Unlock()
	}()
	piper.PipeConn(next, key)
}
