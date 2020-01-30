package main

import (
	"github.com/kataras/golog"
	"noone/conf"
	"noone/transport/tcp"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// set log level
	golog.SetLevel("debug")

	golog.Info("Noone started!")

	conf.LoadJson("/etc/shadowsocks.json")

	go tcp.Run()
	// go udp.Run()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
