package main

import (
	"errors"
	"flag"
	"noone/app/config"
	"noone/app/manager"
	"noone/app/transport/ss"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/sirupsen/logrus"
)

func runOne(p *config.Proxy) error {
	if _, ok := manager.M.UsedPorts[p.Port]; ok {
		return errors.New(strconv.Itoa(p.Port) + " has been used")
	}
	manager.M.UsedPorts[p.Port] = struct{}{}
	ss.Run(p)
	return nil
}

func main() {
	var flags struct {
		confPath string
		logLevel int
	}
	flag.StringVar(&flags.confPath, "c", "config.yaml", "config file path")
	flag.IntVar(&flags.logLevel, "l", int(logrus.InfoLevel), "log level")
	flag.Parse()

	customFormatter := new(logrus.JSONFormatter)
	customFormatter.TimestampFormat = "2006-01-02T15:04:05.000Z07"
	logrus.SetFormatter(customFormatter)
	logrus.SetLevel(logrus.Level(flags.logLevel))

	pwd, _ := os.Getwd()
	logrus.Debugf("current pwd is %s", pwd)

	conf, err := config.LoadConf(flags.confPath)
	if err != nil {
		logrus.Fatal(err)
	}

	manager.Init(conf)

	for _, p := range conf.Proxies {
		if err := runOne(p); err != nil {
			logrus.Fatal(err)
		}
	}

	logrus.Info("Noone started")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
