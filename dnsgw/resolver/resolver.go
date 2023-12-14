package main

import (
	"context"
	"net"
	"os"
	"time"

	"github.com/codingeasygo/tun2conn/dnsgw"
	"github.com/codingeasygo/tun2conn/log"
)

func main() {
	ln, err := net.ListenPacket("udp", os.Args[1])
	if err != nil {
		panic(err)
	}
	buffer := make([]byte, 2048)
	resolver := dnsgw.NewResolver()
	for {
		n, from, err := ln.ReadFrom(buffer)
		if err != nil {
			log.InfoLog("Resolver ln is stopped by %v", err)
			break
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		recrod, _ := resolver.Query(ctx, buffer[0:n])
		cancel()
		if len(recrod) > 0 {
			ln.WriteTo(recrod, from)
		}
	}
}
