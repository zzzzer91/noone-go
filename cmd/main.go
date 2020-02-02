package main

import (
	"fmt"
	"github.com/kataras/golog"
	"noone/conf"
	"noone/transport/tcp"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	golog.SetLevel("debug")

	golog.Info("Noone started!")

	conf.LoadJson("/etc/shadowsocks.json")

	addr := fmt.Sprintf("%s:%d", conf.S.Server, conf.S.ServerPort)
	go tcp.Run(addr)
	// go udp.Run(addr)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
