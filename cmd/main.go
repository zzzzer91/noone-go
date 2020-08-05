package main

import (
	"errors"
	"flag"
	"github.com/sirupsen/logrus"
	"noone/app/conf"
	"noone/app/manager"
	"noone/app/transport/tcp"
	"noone/app/transport/udp"
	"noone/app/user"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
)

func runOne(u *user.User) error {
	if _, ok := manager.M.UsedPorts[u.Port]; ok {
		return errors.New(strconv.Itoa(u.Port) + " has been used")
	}
	manager.M.UsedPorts[u.Port] = struct{}{}
	go tcp.Run(u)
	go udp.Run(u)
	return nil
}

func main() {
	var flags struct {
		confPath string
		logLevel int
	}
	flag.StringVar(&flags.confPath, "c", "config.json", "config file path")
	flag.IntVar(&flags.logLevel, "l", int(logrus.InfoLevel), "log level")
	flag.Parse()

	ssConf, err := conf.LoadJson(flags.confPath)
	if err != nil {
		logrus.Fatal(err)
	}

	customFormatter := new(logrus.TextFormatter)
	customFormatter.FullTimestamp = true
	logrus.SetFormatter(customFormatter)
	logrus.SetLevel(logrus.Level(flags.logLevel))

	manager.M.Users = user.InitUsers(ssConf)
	manager.M.TcpCtxPool = &sync.Pool{
		New: func() interface{} {
			return tcp.NewCtx()
		},
	}

	for _, u := range manager.M.Users {
		if err := runOne(u); err != nil {
			logrus.Fatal(err)
		}
	}

	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for range t.C {
			logrus.Debug("Clear the expired DNS caches regularly")
			for _, u := range manager.M.Users {
				u.DnsCache.Clear()
			}
		}
	}()

	logrus.Info("Noone started")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
