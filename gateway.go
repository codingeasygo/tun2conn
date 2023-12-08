package tun2conn

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/codingeasygo/tun2conn/dnsgw"
	"github.com/codingeasygo/tun2conn/log"
	"github.com/codingeasygo/tun2conn/udpgw"
	"github.com/codingeasygo/util/converter"
	"github.com/codingeasygo/util/xdebug"
	"github.com/codingeasygo/util/xio"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type Gateway struct {
	MAC        string
	Addr       string
	DNS        string
	MTU        int
	Policy     func(on string, ip net.IP, port uint16, domain, cname string) (uri string, newIP net.IP, newPort uint16)
	Dialer     xio.PiperDialer
	BufferSize int
	Stack      *stack.Stack
	device     io.ReadWriteCloser
	link       *LinkEndpoint
	proto      tcpip.NetworkProtocolNumber
	dnsCache   *dnsgw.Cache
	dnsAddr    tcpip.FullAddress
	dnsConn    *gwConnUDP
	dnsGw      *dnsgw.Forwarder
	udpConn    *gwConnUDP
	udpGw      *udpgw.Forwarder
	tcpGw      *gwListenerTCP
	waiter     sync.WaitGroup
}

func NewGateway(device io.ReadWriteCloser, addr, dns string) (gateway *Gateway) {
	gateway = &Gateway{
		MAC:        "aa:00:01:01:01:01",
		Addr:       addr,
		DNS:        dns,
		MTU:        1500,
		Dialer:     xio.PiperDialerF(xio.DialNetPiper),
		BufferSize: 2048,
		device:     device,
		dnsCache:   dnsgw.NewCache(),
		waiter:     sync.WaitGroup{},
	}
	gateway.Stack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	return
}

func (g *Gateway) Start() (err error) {
	// Parse the mac address.
	maddr, err := net.ParseMAC(g.MAC)
	if err != nil {
		err = fmt.Errorf("bad MAC address: %v", g.MAC)
		return
	}

	// Parse the IP address. Support both ipv4 and ipv6.
	addrParts := strings.SplitN(g.Addr, "/", 2)
	if len(addrParts) != 2 {
		err = fmt.Errorf("bad IP address: %v", g.Addr)
		return
	}
	addrIP, err := netip.ParseAddr(addrParts[0])
	if err != nil {
		err = fmt.Errorf("bad IP address: %v", g.Addr)
		return
	}
	addrLen, err := converter.IntVal(addrParts[1])
	if err != nil {
		err = fmt.Errorf("bad IP address: %v", g.Addr)
		return
	}
	addrPrefix := tcpip.AddressWithPrefix{
		PrefixLen: addrLen,
	}
	protocolAddr := tcpip.ProtocolAddress{}
	if addrIP.Is4() {
		addrPrefix.Address = tcpip.AddrFrom4(addrIP.As4())
		protocolAddr.Protocol = ipv4.ProtocolNumber
		protocolAddr.AddressWithPrefix = addrPrefix
		g.proto = ipv4.ProtocolNumber
	} else {
		addrPrefix.Address = tcpip.AddrFrom16(addrIP.As16())
		protocolAddr.Protocol = ipv6.ProtocolNumber
		protocolAddr.AddressWithPrefix = addrPrefix
		g.proto = ipv6.ProtocolNumber
	}

	if len(g.DNS) > 0 {
		dnsIP, xerr := netip.ParseAddr(g.DNS)
		if xerr != nil {
			err = fmt.Errorf("bad DNS address: %v", g.Addr)
			return
		}
		dnsPort := 53
		if dnsIP.Is4() {
			g.dnsAddr = tcpip.FullAddress{Addr: tcpip.AddrFrom4(dnsIP.As4()), Port: uint16(dnsPort)}
		} else {
			g.dnsAddr = tcpip.FullAddress{Addr: tcpip.AddrFrom16(dnsIP.As16()), Port: uint16(dnsPort)}
		}
	}

	g.link = NewLinkEndpoint(uint32(g.MTU), tcpip.LinkAddress(maddr), g.writeDevice)
	if xerr := g.Stack.CreateNIC(1, g.link); xerr != nil {
		err = fmt.Errorf("CreateNIC error %v", xerr)
		return
	}
	g.Stack.SetPromiscuousMode(1, true)
	g.Stack.SetSpoofing(1, true)
	g.Stack.AddProtocolAddress(1, protocolAddr, stack.AddressProperties{})
	subnet, _ := tcpip.NewSubnet(tcpip.AddrFromSlice([]byte(strings.Repeat("\x00", addrPrefix.Address.Len()))), tcpip.MaskFrom(strings.Repeat("\x00", addrPrefix.Address.Len())))

	// Add default route.
	g.Stack.SetRouteTable([]tcpip.Route{
		{
			Destination: subnet,
			NIC:         1,
		},
	})

	//start all
	defer func() {
		if err != nil {
			g.stopDevice()
			g.stopDNS()
			g.stopUDP()
			g.stopTCP()
		}
	}()
	g.startDevice()
	if len(g.DNS) > 0 && err == nil {
		err = g.startDNS()
	}
	if err == nil {
		err = g.startUDP()
	}
	if err == nil {
		err = g.startTCP()
	}
	return
}

func (g *Gateway) Stop() (err error) {
	g.stopDNS()
	g.stopUDP()
	g.stopTCP()
	g.link.Close()
	g.Stack.Close()
	g.stopDevice()
	g.waiter.Wait()
	return
}

func (g *Gateway) startDevice() {
	g.waiter.Add(1)
	go g.procDevice()
}

func (g *Gateway) stopDevice() {
	if g.device != nil {
		g.device.Close()
	}
}

func (g *Gateway) procDevice() {
	defer func() {
		g.device.Close()
		g.waiter.Done()
	}()
	log.InfoLog("Gateway read device(%v) is started", g.device)
	buffer := make([]byte, g.MTU)
	for {
		n, err := g.device.Read(buffer)
		if err != nil {
			log.InfoLog("Gateway read device(%v) is done by %v", g.device, err)
			break
		}
		g.link.Recv(buffer[:n])
	}
}

func (g *Gateway) writeDevice(p []byte) (_ tcpip.Error) {
	_, err := g.device.Write(p)
	if err != nil {
		log.WarnLog("Gateway write device(%v) error %v", g.device, err)
	}
	return
}

func (g *Gateway) startDNS() (err error) {
	dnsConn, err := newGwConnUDP(g, g.proto, g.dnsAddr)
	if err != nil {
		return
	}
	g.dnsConn = dnsConn
	g.waiter.Add(1)
	go g.procDNS()
	return
}

func (g *Gateway) stopDNS() {
	if g.dnsConn != nil {
		g.dnsConn.Close()
	}
}

func (g *Gateway) procDNS() {
	conn := dnsgw.NewConn(newGwConnPacketConn("dnsgw", g, g.dnsConn))
	defer func() {
		conn.Close()
		g.waiter.Done()
	}()
	g.dnsGw = dnsgw.NewForwarder(g.Dialer, g.BufferSize)
	g.dnsGw.Policy = g.policyDNS
	g.dnsGw.ServeConn(conn)
}

func (g *Gateway) policyDNS(conid uint16, domain ...string) (key string) {
	if g.Policy == nil {
		key = "tcp://dnsgw"
		return
	}
	key, _, _ = g.Policy("dns", nil, 0, domain[0], "")
	return
}

func (g *Gateway) startUDP() (err error) {
	udpConn, err := newGwConnUDP(g, g.proto, tcpip.FullAddress{})
	if err != nil {
		log.ErrorLog("Gateway start udp gw fail with %v", err)
		return
	}
	g.udpConn = udpConn
	g.waiter.Add(1)
	go g.procUDP()
	return
}

func (g *Gateway) stopUDP() {
	if g.udpConn != nil {
		g.udpConn.Close()
	}
}

func (g *Gateway) procUDP() {
	conn := udpgw.NewConn(newGwConnPacketConn("udpgw", g, g.udpConn), g.proto == ipv6.ProtocolNumber)
	defer func() {
		conn.Close()
		g.waiter.Done()
	}()
	g.udpGw = udpgw.NewForwarder(g.Dialer, g.BufferSize)
	g.udpGw.Policy = g.policyUDP
	g.udpGw.ServeConn(conn)
}

func (g *Gateway) policyUDP(id uint16, ip net.IP, port uint16) (uri string, newIP net.IP, newPort uint16) {
	if g.Policy == nil {
		uri = "tcp://udpgw"
		return
	}
	domain, cname, _ := g.dnsCache.Reflect(ip.String())
	uri, newIP, newPort = g.Policy("udp", ip, port, domain, cname)
	return
}

func (g *Gateway) startTCP() (err error) {
	g.tcpGw, err = newGwListenerTCP(g, g.proto, g.Dialer, g.BufferSize)
	if err != nil {
		return
	}
	g.tcpGw.Policy = g.policyTCP
	g.waiter.Add(1)
	go g.procTCP()
	return
}

func (g *Gateway) stopTCP() {
	if g.tcpGw != nil {
		g.tcpGw.Close()
	}
}

func (g *Gateway) procTCP() {
	defer func() {
		g.tcpGw.Close()
		g.waiter.Done()
	}()
	g.tcpGw.AcceptConn()
}

func (g *Gateway) policyTCP(ip net.IP, port uint16) (uri string) {
	if g.Policy == nil {
		return fmt.Sprintf("tcp://%v:%v", ip, port)
	}
	domain, cname, _ := g.dnsCache.Reflect(ip.String())
	uri, _, _ = g.Policy("tcp", ip, port, domain, cname)
	return
}

type gwListenerTCP struct {
	Policy     func(net.IP, uint16) string
	wq         *waiter.Queue
	ep         tcpip.Endpoint
	wait       waiter.Entry
	notify     chan struct{}
	connAll    map[string]tcpip.Endpoint
	connLock   sync.RWMutex
	waiter     sync.WaitGroup
	Dialer     xio.PiperDialer
	BufferSize int
}

func newGwListenerTCP(gw *Gateway, proto tcpip.NetworkProtocolNumber, dialer xio.PiperDialer, bufferSize int) (ln *gwListenerTCP, err error) {
	var wq waiter.Queue
	ep, xerr := gw.Stack.NewEndpoint(tcp.ProtocolNumber, proto, &wq)
	if xerr != nil {
		err = fmt.Errorf("NewEndpoint error %v", xerr)
		return
	}

	xerr = ep.Listen(10)
	if xerr != nil {
		err = fmt.Errorf("listen error %v", xerr)
		ep.Close()
		return
	}

	ln = &gwListenerTCP{
		wq:         &wq,
		ep:         ep,
		connAll:    map[string]tcpip.Endpoint{},
		connLock:   sync.RWMutex{},
		waiter:     sync.WaitGroup{},
		Dialer:     dialer,
		BufferSize: bufferSize,
	}
	ln.wait, ln.notify = waiter.NewChannelEntry(waiter.ReadableEvents)
	wq.EventRegister(&ln.wait)
	return
}

func (g *gwListenerTCP) AcceptConn() error {
	for {
		ep, wq, xerr := g.ep.Accept(nil)
		if xerr != nil {
			if _, ok := xerr.(*tcpip.ErrWouldBlock); ok {
				<-g.notify
				continue
			}
			return fmt.Errorf("accept %v", xerr)
		}
		g.connLock.Lock()
		g.connAll[fmt.Sprintf("%p", ep)] = ep
		g.connLock.Unlock()
		g.waiter.Add(1)
		go g.procConn(ep, wq)
	}
}

func (g *gwListenerTCP) procConn(ep tcpip.Endpoint, wq *waiter.Queue) {
	defer func() {
		if perr := recover(); perr != nil {
			log.ErrorLog("Gateway proc tcp connec is panic with %v, callstack is \n%v", perr, xdebug.CallStack())
		}
		g.waiter.Done()
		ep.Close()
		g.connLock.Lock()
		delete(g.connAll, fmt.Sprintf("%p", ep))
		g.connLock.Unlock()
	}()
	laddr, _ := ep.GetLocalAddress()
	raddr, _ := ep.GetRemoteAddress()
	lip := net.IP(laddr.Addr.AsSlice())
	uri := fmt.Sprintf("tcp://%v:%v", laddr.Addr, laddr.Port)
	if g.Policy != nil {
		uri = g.Policy(lip, laddr.Port)
	}
	piper, err := g.Dialer.DialPiper(uri, g.BufferSize)
	if err != nil {
		log.InfoLog("Gateway dial to %v fail with %v", uri, err)
		return
	}
	log.DebugLog("Gateway start transfer %v:%v=>%v", raddr.Addr, raddr.Port, uri)
	conn := newGwConnTCP(ep, wq)
	err = piper.PipeConn(conn, uri)
	conn.Close()
	log.DebugLog("Gateway transfer %v:%v=>%v is done by %v", raddr.Addr, raddr.Port, uri, err)
}

func (g *gwListenerTCP) Close() (err error) {
	g.ep.Close()
	g.wq.EventUnregister(&g.wait)
	epAll := []tcpip.Endpoint{}
	g.connLock.RLock()
	for _, ep := range g.connAll {
		epAll = append(epAll, ep)
	}
	g.connLock.RUnlock()
	for _, ep := range epAll {
		ep.Close()
	}
	return
}

type gwConnTCP struct {
	ep     tcpip.Endpoint
	wq     *waiter.Queue
	wait   waiter.Entry
	notify chan struct{}
}

func newGwConnTCP(ep tcpip.Endpoint, wq *waiter.Queue) (conn *gwConnTCP) {
	conn = &gwConnTCP{
		ep: ep,
		wq: wq,
	}
	conn.wait, conn.notify = waiter.NewChannelEntry(waiter.ReadableEvents)
	wq.EventRegister(&conn.wait)
	return
}

func (g *gwConnTCP) Read(p []byte) (int, error) {
	buf := bytes.NewBuffer(p)
	buf.Reset()
	for {
		if _, err := g.ep.Read(buf, tcpip.ReadOptions{}); err != nil {
			if _, ok := err.(*tcpip.ErrWouldBlock); ok {
				<-g.notify
				continue
			}
			return 0, fmt.Errorf("ep read %v", err)
		}
		return buf.Len(), nil
	}
}

func (g *gwConnTCP) Write(p []byte) (n int, err error) {
	var buffer bytes.Reader
	buffer.Reset(p)
	writed, xerr := g.ep.Write(&buffer, tcpip.WriteOptions{Atomic: true})
	if xerr != nil {
		err = fmt.Errorf("ep write %v", xerr)
	}
	n = int(writed)
	return
}

func (g *gwConnTCP) Close() (err error) {
	g.wq.EventUnregister(&g.wait)
	g.ep.Close()
	return
}

type gwConnUDP struct {
	addr   tcpip.FullAddress
	wq     *waiter.Queue
	ep     tcpip.Endpoint
	wait   waiter.Entry
	notify chan struct{}
}

func newGwConnUDP(gw *Gateway, proto tcpip.NetworkProtocolNumber, addr tcpip.FullAddress) (conn *gwConnUDP, err error) {
	var wq waiter.Queue
	ep, xerr := gw.Stack.NewEndpoint(udp.ProtocolNumber, proto, &wq)
	if xerr != nil {
		err = fmt.Errorf("NewEndpoint error %v", xerr)
		return
	}

	xerr = ep.Bind(addr)
	if xerr != nil {
		err = fmt.Errorf("bind error %v", xerr)
		ep.Close()
		return
	}

	conn = &gwConnUDP{
		addr: addr,
		wq:   &wq,
		ep:   ep,
	}
	conn.wait, conn.notify = waiter.NewChannelEntry(waiter.ReadableEvents)
	wq.EventRegister(&conn.wait)
	return
}

func (g *gwConnUDP) ReadFrom(p []byte) (n int, laddr, raddr *tcpip.FullAddress, err error) {
	buffer := bytes.NewBuffer(p)
	buffer.Reset()
	for {
		result, xerr := g.ep.Read(buffer, tcpip.ReadOptions{NeedRemoteAddr: true})
		if xerr != nil {
			if _, ok := xerr.(*tcpip.ErrWouldBlock); ok {
				<-g.notify
				continue
			}
			return 0, nil, nil, fmt.Errorf("read error %v", xerr)
		}
		return buffer.Len(), &result.LocalAddr, &result.RemoteAddr, nil
	}
}

func (g *gwConnUDP) WriteTo(p []byte, from, to *tcpip.FullAddress) (n int, err error) {
	var buffer bytes.Reader
	buffer.Reset(p)
	_, xerr := g.ep.Write(&buffer, tcpip.WriteOptions{From: from, To: to})
	if xerr != nil {
		err = fmt.Errorf("write error %v", xerr)
	}
	return
}

func (g *gwConnUDP) Close() (err error) {
	g.ep.Close()
	g.wq.EventUnregister(&g.wait)
	return
}

type gwAddr struct {
	network string
	addr    *tcpip.FullAddress
}

func newGwAddr(network string, addr *tcpip.FullAddress) (a *gwAddr) {
	a = &gwAddr{
		network: network,
		addr:    addr,
	}
	return
}

func (g *gwAddr) Network() string {
	return g.network
}

func (g *gwAddr) String() string {
	return fmt.Sprintf("%v:%v", g.addr.Addr, g.addr.Port)
}

type gwConnID struct {
	*gwAddr
	local *gwAddr
}

func newGwConnID(network string, local, remote *tcpip.FullAddress) (id *gwConnID) {
	id = &gwConnID{
		gwAddr: newGwAddr(network, remote),
		local:  newGwAddr(network, local),
	}
	return
}

func (g *gwConnID) LocalAddr() net.Addr {
	return g.local
}

func (g *gwConnID) LocalIP() net.IP {
	return net.ParseIP(g.local.addr.Addr.String())
}

func (g *gwConnID) LocalPort() uint16 {
	return g.local.addr.Port
}

func (g *gwConnID) String() string {
	return fmt.Sprintf("%v:%v=>%v:%v", g.local.addr.Addr, g.local.addr.Port, g.gwAddr.addr.Addr, g.gwAddr.addr.Port)
}

type gwConnPacketConn struct {
	name string
	gw   *Gateway
	base *gwConnUDP
}

func newGwConnPacketConn(name string, gw *Gateway, base *gwConnUDP) (conn *gwConnPacketConn) {
	conn = &gwConnPacketConn{
		name: name,
		gw:   gw,
		base: base,
	}
	return
}

func (g *gwConnPacketConn) String() string {
	return g.name
}

func (g *gwConnPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, laddr, raddr, err := g.base.ReadFrom(p)
	if err == nil {
		addr = newGwConnID("udp", laddr, raddr)
	}
	return
}

func (g *gwConnPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	id := addr.(*gwConnID)
	n, err = g.base.WriteTo(p, id.local.addr, id.gwAddr.addr)
	return
}

func (g *gwConnPacketConn) Close() error {
	err := g.base.Close()
	return err
}

func (g *gwConnPacketConn) LocalAddr() net.Addr {
	return newGwAddr("udp", &g.base.addr)
}

func (g *gwConnPacketConn) SetDeadline(t time.Time) error {
	return nil
}

func (g *gwConnPacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (g *gwConnPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}
