package tun2conn

import (
	"net"
	"os"
	"sync"

	"github.com/codingeasygo/tun2conn/log"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type PacketReader interface {
	ReadPacket() (pkt *stack.PacketBuffer, err error)
}

type LinkEndpoint struct {
	mtu        uint32
	addr       tcpip.LinkAddress
	caps       stack.LinkEndpointCapabilities
	send       func([]byte) tcpip.Error
	waiter     sync.WaitGroup
	dispatcher stack.NetworkDispatcher
}

func NewLinkEndpoint(mtu uint32, addr tcpip.LinkAddress, send func([]byte) tcpip.Error) (ep *LinkEndpoint) {
	ep = &LinkEndpoint{
		mtu:    mtu,
		addr:   addr,
		caps:   stack.LinkEndpointCapabilities(0),
		send:   send,
		waiter: sync.WaitGroup{},
	}
	ep.waiter.Add(1)
	return
}

func (e *LinkEndpoint) Close() (err error) {
	e.waiter.Done()
	return
}

func (e *LinkEndpoint) MTU() uint32 {
	return e.mtu
}

func (e *LinkEndpoint) MaxHeaderLength() uint16 {
	return 0
}

func (e *LinkEndpoint) LinkAddress() tcpip.LinkAddress {
	return e.addr
}

func (e *LinkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.caps
}

func (e *LinkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
}

func (e *LinkEndpoint) IsAttached() bool {
	return e.dispatcher != nil
}

func (e *LinkEndpoint) Wait() {
	e.waiter.Wait()
}

func (e *LinkEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (e *LinkEndpoint) AddHeader(ptr stack.PacketBufferPtr) {
}

func (e *LinkEndpoint) ParseHeader(ptr stack.PacketBufferPtr) bool {
	return false
}

func (e *LinkEndpoint) sendPacket(pkt stack.PacketBufferPtr) (err tcpip.Error) {
	buffer := []byte{}
	for _, view := range pkt.AsSlices() {
		buffer = append(buffer, view...)
	}
	err = e.send(buffer)
	return
}

func (e *LinkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	sentPackets := 0
	for _, pkt := range pkts.AsSlice() {
		err := e.sendPacket(pkt)
		if err != nil {
			return sentPackets, err
		}
		sentPackets += 1
	}
	return sentPackets, nil
}

func (e *LinkEndpoint) RecvBuffer(p []byte) {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(p),
	})
	e.RecvPacket(pkt)
}

func (e *LinkEndpoint) RecvPacket(pkt *stack.PacketBuffer) {
	h, ok := pkt.Data().PullUp(1)
	if !ok {
		log.WarnLog("LinkEndpoint recv nvalid packet: %02x", pkt.AsSlices())
		return
	}
	dispatcher := e.dispatcher
	if dispatcher != nil {
		switch header.IPVersion(h) {
		case header.IPv4Version:
			dispatcher.DeliverNetworkPacket(header.IPv4ProtocolNumber, pkt)
		case header.IPv6Version:
			dispatcher.DeliverNetworkPacket(header.IPv6ProtocolNumber, pkt)
		default:
			log.WarnLog("LinkEndpoint recv nvalid packet: %02x", pkt.AsSlices())
		}
	}
	pkt.DecRef()
}

type PacketConnDevice struct {
	net.PacketConn
	fromAddr net.Addr
}

func NewPacketConnDevice(conn net.PacketConn) (device *PacketConnDevice) {
	device = &PacketConnDevice{PacketConn: conn}
	return
}

func (c *PacketConnDevice) Read(p []byte) (n int, err error) {
	n, c.fromAddr, err = c.PacketConn.ReadFrom(p)
	return
}

func (c *PacketConnDevice) Write(p []byte) (n int, err error) {
	if c.fromAddr == nil {
		n = len(p)
	} else {
		n, err = c.PacketConn.WriteTo(p, c.fromAddr)
	}
	return
}

type FileDevice struct {
	*os.File
	FD uintptr
}

func NewFileDevice(fd uintptr, name string) (device *FileDevice) {
	device = &FileDevice{
		FD:   fd,
		File: os.NewFile(fd, name),
	}
	return
}
