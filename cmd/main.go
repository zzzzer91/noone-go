package main

import (
	"flag"
	"github.com/kataras/golog"
	"noone/conf"
	"noone/crypto"
	"noone/dnscache"
	"noone/transport/tcp"
	"noone/transport/udp"
	"noone/user"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	var flags struct {
		confPath string
		logLevel string
	}
	flag.StringVar(&flags.confPath, "c", "config.json", "config file path")
	flag.StringVar(&flags.logLevel, "l", "info", "log level")
	flag.Parse()

	ssConf, err := conf.LoadJson(flags.confPath)
	if err != nil {
		golog.Fatal(err)
	}
	golog.SetLevel(flags.logLevel)

	golog.Info("Noone started!")

	userInfo := &user.Info{
		Port:     ssConf.ServerPort,
		Method:   ssConf.Method,
		Password: ssConf.Password,
		Key:      crypto.Kdf(ssConf.Password, 16),
		DnsCache: dnscache.NewCache(),
	}
	// 开个协程定时清理 DNS 缓存
	go func() {
		time.Sleep(5 * time.Minute)
		golog.Debug("定时清理 DNS 缓存")
		userInfo.DnsCache.Clear()
	}()
	go tcp.Run(userInfo)
	go udp.Run(userInfo)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
