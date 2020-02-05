package main

import (
	"flag"
	"fmt"
	"github.com/kataras/golog"
	"noone/conf"
	"noone/transport/tcp"
	"noone/transport/udp"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	var flags struct {
		confPath string
		logLevel string
	}
	flag.StringVar(&flags.confPath, "c", "config.json", "config file path")
	flag.StringVar(&flags.logLevel, "l", "info", "log level")
	flag.Parse()

	if err := conf.LoadJson(flags.confPath); err != nil {
		golog.Fatal(err)
	}
	golog.SetLevel(flags.logLevel)

	golog.Info("Noone started!")

	addr := fmt.Sprintf("%s:%d", conf.SS.Server, conf.SS.ServerPort)
	go tcp.Run(addr)
	go udp.Run(addr)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
