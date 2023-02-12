package main

import (
	"errors"
	"flag"
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

	"github.com/sirupsen/logrus"
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

	customFormatter := new(logrus.JSONFormatter)
	logrus.SetFormatter(customFormatter)
	logrus.SetLevel(logrus.Level(flags.logLevel))

	pwd, _ := os.Getwd()
	logrus.Debugf("current pwd is %s", pwd)

	ssConf, err := conf.LoadJson(flags.confPath)
	if err != nil {
		logrus.Fatal(err)
	}

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

	logrus.Info("Noone started")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
