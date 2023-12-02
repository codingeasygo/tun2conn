package tun2conn

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/codingeasygo/tun2conn/log"
	"github.com/codingeasygo/util/xdebug"
	"github.com/codingeasygo/util/xio"
	"github.com/codingeasygo/util/xio/frame"
)

const CLIENT_FLAG_KEEPALIVE = (1 << 0)
const CLIENT_FLAG_REBIND = (1 << 1)
const CLIENT_FLAG_DNS = (1 << 2)
const CLIENT_FLAG_IPV6 = (1 << 3)

var allGateway = map[string]*Gateway{}
var allGatewayLock = sync.RWMutex{}
var allGatewayRunning = false
var timeoutExit = make(chan int, 1)
var timeoutWait = make(chan int, 1)

func StartTimeout(delay, timeout time.Duration) {
	if allGatewayRunning {
		panic("running")
	}
	allGatewayRunning = true
	go runTimeout(delay, timeout)
}

func StopTimeout() {
	timeoutExit <- 1
	<-timeoutWait
	allGatewayRunning = false
}

func runTimeout(delay, timeout time.Duration) {
	ticker := time.NewTicker(delay)
	running := true
	for running {
		select {
		case <-timeoutExit:
			running = false
		case <-ticker.C:
			procTimeout(timeout)
		}
	}
	timeoutWait <- 1
}

func procTimeout(timeout time.Duration) {
	defer func() {
		if perr := recover(); perr != nil {
			log.WarnLog("Gateway process timeout is panic by %v, callstack is \n%v", perr, xdebug.CallStack())
		}
	}()
	gwAll := []*Gateway{}
	allGatewayLock.RLock()
	for _, gw := range allGateway {
		gwAll = append(gwAll, gw)
	}
	allGatewayLock.RUnlock()
	for _, gw := range gwAll {
		gw.timeoutConn(timeout)
	}
}

func StateH(w http.ResponseWriter, r *http.Request) {
	info := map[string]interface{}{}
	allGatewayLock.Lock()
	for k, u := range allGateway {
		udpgw := map[string]interface{}{}
		u.connLock.Lock()
		for key, conn := range u.connList {
			udpgw[fmt.Sprintf("_%v", key)] = map[string]interface{}{
				"addr":   conn.raw.RemoteAddr(),
				"conid":  conn.conid,
				"latest": conn.latest.Unix(),
			}
		}
		u.connLock.Unlock()
		info[k] = udpgw
	}
	allGatewayLock.Unlock()
	w.Header().Add("Content-Type", "application/json;charset=utf-8")
	data, _ := json.Marshal(info)
	w.Write(data)
}

type gwConn struct {
	raw    *net.UDPConn
	addr   *net.UDPAddr
	orig   *net.UDPAddr
	conid  uint16
	flags  uint8
	latest time.Time
}

type Gateway struct {
	MTU      int
	DNS      *net.UDPAddr
	MaxConn  int
	connPipe io.ReadWriteCloser
	connList map[uint16]*gwConn
	connLock sync.RWMutex
}

func NewGateway() (gw *Gateway) {
	gw = &Gateway{
		MTU:      2048,
		MaxConn:  16,
		connList: map[uint16]*gwConn{},
		connLock: sync.RWMutex{},
	}
	return
}

func DialGateway(uri string, bufferSize int) (raw xio.Piper, err error) {
	raw = NewGateway()
	return
}

func (u *Gateway) timeoutConn(max time.Duration) {
	now := time.Now()
	connAll := []*gwConn{}
	u.connLock.Lock()
	for key, conn := range u.connList {
		if now.Sub(conn.latest) > max {
			delete(u.connList, key)
			connAll = append(connAll, conn)
		}
	}
	u.connLock.Unlock()
	for _, conn := range connAll {
		conn.raw.Close()
	}
}

func (u *Gateway) cloaseAllConn() {
	u.connLock.Lock()
	for connid, conn := range u.connList {
		conn.raw.Close()
		delete(u.connList, connid)
	}
	u.connLock.Unlock()
}

func (u *Gateway) Close() (err error) {
	u.cloaseAllConn()
	if u.connPipe != nil {
		u.connPipe.Close()
	}
	return
}

func (u *Gateway) PipeConn(conn io.ReadWriteCloser, target string) (err error) {
	defer func() {
		conn.Close()
		u.cloaseAllConn()
		allGatewayLock.Lock()
		delete(allGateway, fmt.Sprintf("%p", u))
		allGatewayLock.Unlock()
		log.InfoLog("Gateway one connection %v is stopped by %v", conn, err)
	}()
	log.InfoLog("Gateway one connection %v is starting", conn)
	rwc, ok := conn.(frame.ReadWriteCloser)
	if !ok {
		err = fmt.Errorf("conn is not frame.ReadWriteCloser")
		return
	}
	u.connPipe = conn
	allGatewayLock.Lock()
	allGateway[fmt.Sprintf("%p", u)] = u
	allGatewayLock.Unlock()
	offset := rwc.GetDataOffset()
	for {
		data, xerr := rwc.ReadFrame()
		if xerr != nil {
			err = xerr
			break
		}
		u.procData(rwc, data[offset:])
	}
	return
}

func (u *Gateway) procData(piped frame.ReadWriteCloser, p []byte) (n int, err error) {
	if len(p) < 3 {
		err = fmt.Errorf("data error")
		return
	}
	flags := uint8(p[0])
	conid := binary.BigEndian.Uint16(p[1:])
	if flags&CLIENT_FLAG_KEEPALIVE == CLIENT_FLAG_KEEPALIVE {
		n = len(p)
		return
	}
	var addrIP net.IP
	var addrPort uint16
	var data []byte
	if flags&CLIENT_FLAG_IPV6 == CLIENT_FLAG_IPV6 {
		addrIP = net.IP(p[3:19])
		addrPort = binary.BigEndian.Uint16(p[19:21])
		data = p[21:]
	} else {
		addrIP = net.IP(p[3:7])
		addrPort = binary.BigEndian.Uint16(p[7:9])
		data = p[9:]
	}
	u.connLock.RLock()
	conn := u.connList[conid]
	u.connLock.RUnlock()
	if conn == nil {
		u.limitConn()
		orig := &net.UDPAddr{IP: addrIP, Port: int(addrPort)}
		addr := &net.UDPAddr{IP: addrIP, Port: int(addrPort)}
		if flags&CLIENT_FLAG_DNS == CLIENT_FLAG_DNS && u.DNS != nil {
			addr = u.DNS
		}
		conn = &gwConn{conid: conid, flags: flags, addr: addr, orig: orig, latest: time.Now()}
		conn.raw, err = net.DialUDP("udp", nil, addr)
		if err != nil {
			log.WarnLog("Gateway udp dial to %v fail with %v", addr, err)
			return
		}
		log.DebugLog("Gateway udp dial to %v success", addr)
		u.connLock.Lock()
		u.connList[conid] = conn
		u.connLock.Unlock()
		go u.procRead(piped, conn)
	}
	conn.latest = time.Now()
	n, err = conn.raw.Write(data)
	n += len(addrIP) + 5
	return
}

func (u *Gateway) procRead(piped frame.ReadWriteCloser, conn *gwConn) {
	var err error
	defer func() {
		if perr := recover(); perr != nil {
			log.WarnLog("Gateway process raw read is panic by %v", perr)
		}
		u.connLock.Lock()
		delete(u.connList, conn.conid)
		u.connLock.Unlock()
		conn.raw.Close()
		log.DebugLog("Gateway read udp from %v is closed by %v", conn.addr, err)
	}()
	buffer := make([]byte, u.MTU+piped.GetDataOffset())
	offset := piped.GetDataOffset()
	if conn.flags&CLIENT_FLAG_IPV6 == CLIENT_FLAG_IPV6 {
		buffer[offset] = CLIENT_FLAG_IPV6
	} else {
		buffer[offset] = 0
	}
	if conn.flags&CLIENT_FLAG_DNS == CLIENT_FLAG_DNS {
		buffer[offset] |= CLIENT_FLAG_DNS
	}
	offset += 1
	binary.BigEndian.PutUint16(buffer[offset:], conn.conid)
	offset += 2
	offset += copy(buffer[offset:], conn.orig.IP)
	binary.BigEndian.PutUint16(buffer[offset:], uint16(conn.orig.Port))
	offset += 2
	var n int
	for {
		n, err = conn.raw.Read(buffer[offset:])
		if err == nil {
			conn.latest = time.Now()
			_, err = piped.WriteFrame(buffer[:offset+n])
		}
		if err != nil {
			break
		}
	}
}

func (u *Gateway) limitConn() {
	u.connLock.Lock()
	defer u.connLock.Unlock()
	if len(u.connList) < u.MaxConn {
		return
	}
	var oldest *gwConn
	for _, conn := range u.connList {
		if oldest == nil || oldest.latest.After(conn.latest) {
			oldest = conn
		}
	}
	if oldest != nil {
		log.DebugLog("Gateway closing connection %v by limit %v/%v", oldest.addr, len(u.connList), u.MaxConn)
		oldest.raw.Close()
		delete(u.connList, oldest.conid)
	}
}

type ConnID interface {
	net.Addr
	LocalAddr() net.Addr
}

type Conn struct {
	MaxAlive time.Duration
	raw      net.PacketConn
	ipv6     bool
	sequence uint16
	idAll    map[uint16]ConnID
	idLast   map[uint16]time.Time
	lock     sync.RWMutex
}

func NewConn(raw net.PacketConn, ipv6 bool) (conn *Conn) {
	conn = &Conn{
		MaxAlive: time.Minute,
		raw:      raw,
		ipv6:     ipv6,
		idAll:    map[uint16]ConnID{},
		idLast:   map[uint16]time.Time{},
		lock:     sync.RWMutex{},
	}
	return
}

func (c *Conn) clearTimeoutLocked() {
	now := time.Now()
	for id, last := range c.idLast {
		if now.Sub(last) > c.MaxAlive {
			delete(c.idAll, id)
			delete(c.idLast, id)
		}
	}
}

func (c *Conn) Read(p []byte) (n int, err error) {
	dataOffset := 9
	if c.ipv6 {
		dataOffset = 21
		p[0] |= CLIENT_FLAG_IPV6
	}
	n, from, err := c.raw.ReadFrom(p[dataOffset:])
	if err != nil {
		return
	}
	fromAddr := from.(ConnID)
	localAddr := fromAddr.LocalAddr().(*net.UDPAddr)
	c.lock.Lock()
	defer c.lock.Unlock()
	c.clearTimeoutLocked()
	c.sequence++
	id := c.sequence
	binary.BigEndian.PutUint16(p[1:], id)
	if c.ipv6 {
		copy(p[3:19], localAddr.IP)
		binary.BigEndian.PutUint16(p[19:21], uint16(localAddr.Port))
	} else {
		copy(p[3:7], localAddr.IP)
		binary.BigEndian.PutUint16(p[7:9], uint16(localAddr.Port))
	}
	c.idAll[id] = fromAddr
	c.idLast[id] = time.Now()
	n += dataOffset
	return
}

func (c *Conn) Write(p []byte) (n int, err error) {
	if len(p) < 3 {
		err = fmt.Errorf("data error")
		return
	}
	flags := uint8(p[0])
	conid := binary.BigEndian.Uint16(p[1:])
	if flags&CLIENT_FLAG_KEEPALIVE == CLIENT_FLAG_KEEPALIVE {
		n = len(p)
		return
	}
	var data []byte
	if flags&CLIENT_FLAG_IPV6 == CLIENT_FLAG_IPV6 {
		data = p[21:]
	} else {
		data = p[9:]
	}
	c.lock.RLock()
	fromAddr := c.idAll[conid]
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
	readBuffer chan []byte
	base       *Conn
}

func newForwarderConn(base *Conn) (conn *forwarderConn) {
	conn = &forwarderConn{
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
	return
}

func (c *forwarderConn) Close() (err error) {
	c.readBuffer <- nil
	return
}

type Forwarder struct {
	BufferSize int
	Policy     func(net.IP, uint16) string
	Dialer     map[string]xio.PiperDialer
	conn       *Conn
	nextAll    map[string]*forwarderConn
	nextLock   sync.RWMutex
	waiter     sync.WaitGroup
}

func NewForwarder(conn *Conn) (forwarder *Forwarder) {
	forwarder = &Forwarder{
		BufferSize: 2048,
		Dialer:     map[string]xio.PiperDialer{},
		conn:       conn,
		nextAll:    map[string]*forwarderConn{},
		nextLock:   sync.RWMutex{},
		waiter:     sync.WaitGroup{},
	}
	return
}

func (f *Forwarder) Start() {
	f.waiter.Add(1)
	go f.loopRead()
}

func (f *Forwarder) Stop() {
	f.conn.Close()
	f.waiter.Wait()
}

func (f *Forwarder) loopRead() {
	defer f.waiter.Done()
	buffer := make([]byte, f.BufferSize)
	for {
		n, err := f.conn.Read(buffer)
		if err != nil {
			log.InfoLog("Forwarder(%v) read is done by %v", f.conn, err)
			break
		}
		f.procData(buffer[:n])
	}
	for _, next := range f.nextAll {
		next.Close()
	}
	f.nextAll = map[string]*forwarderConn{}
}

func (f *Forwarder) procData(buffer []byte) {
	defer func() {
		if perr := recover(); perr != nil {
			log.ErrorLog("Forward(%v) proc data is panic with %v, callstack is \n%v", f.conn, perr, xdebug.CallStack())
		}
	}()
	key := "*"
	if f.Policy != nil {
		flags := uint8(buffer[0])
		var addrIP net.IP
		var addrPort uint16
		if flags&CLIENT_FLAG_IPV6 == CLIENT_FLAG_IPV6 {
			addrIP = net.IP(buffer[3:19])
			addrPort = binary.BigEndian.Uint16(buffer[19:21])
		} else {
			addrIP = net.IP(buffer[3:7])
			addrPort = binary.BigEndian.Uint16(buffer[7:9])
		}
		key = f.Policy(addrIP, addrPort)
	}
	f.nextLock.RLock()
	next := f.nextAll[key]
	f.nextLock.RUnlock()
	if next == nil {
		dialer := f.Dialer[key]
		if dialer == nil {
			log.WarnLog("Forwarder(%v) %v dialer is not supported", f.conn, key)
			return
		}
		piper, err := dialer.DialPiper(key, f.BufferSize)
		if err != nil {
			log.WarnLog("Forwarder(%v) %v dialer dial piper by %v fail with %v", f.conn, key, key, err)
			return
		}
		next = newForwarderConn(f.conn)
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
