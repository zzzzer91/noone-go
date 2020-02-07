package main

import (
	"errors"
	"flag"
	"github.com/kataras/golog"
	"noone/conf"
	"noone/manager"
	"noone/transport/tcp"
	"noone/transport/udp"
	"noone/user"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func runOne(u *user.User) error {
	if _, ok := manager.M.UsedPorts[u.Port]; ok {
		return errors.New(strconv.Itoa(u.Port) + " is used")
	}
	manager.M.UsedPorts[u.Port] = struct{}{}
	go tcp.Run(u)
	go udp.Run(u)
	return nil
}

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

	manager.M.Users = user.InitUsers(ssConf)

	for _, u := range manager.M.Users {
		if err := runOne(u); err != nil {
			golog.Error(err)
		}
	}

	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for range t.C {
			golog.Debug("Clear the expired DNS caches regularly")
			for _, u := range manager.M.Users {
				u.DnsCache.Clear()
			}
		}
	}()

	golog.Info("Noone started")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
