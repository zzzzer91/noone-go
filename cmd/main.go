package main

import (
	"fmt"
	"github.com/kataras/golog"
	"noone/conf"
	"noone/transport"
	"noone/transport/tcp"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

func main() {
	golog.SetLevel("debug")

	golog.Info("Noone started!")

	conf.LoadJson("/etc/shadowsocks.json")

	pool := &sync.Pool{
		New: func() interface{} {
			return transport.New()
		},
	}
	addr := fmt.Sprintf("%s:%d", conf.S.Server, conf.S.ServerPort)
	go tcp.Run(pool, addr)
	// go udp.Run(pool, addr)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
