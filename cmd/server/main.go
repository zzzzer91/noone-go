package main

import (
	"errors"
	"flag"
	"noone/app/config"
	"noone/app/manager"
	"noone/app/transport/ss"
	"noone/app/transport/trojan"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/zzzzer91/gopkg/logx"
)

func runOne(p *config.Proxy) error {
	if _, ok := manager.M.UsedPorts[p.Port]; ok {
		return errors.New(strconv.Itoa(p.Port) + " has been used")
	}
	manager.M.UsedPorts[p.Port] = struct{}{}
	switch p.Type {
	case "ss":
		ss.Run(p)
	case "trojan":
		trojan.Run(p)
	default:
		return errors.New("proxy type is invalid")
	}
	return nil
}

func main() {
	var flags struct {
		confPath string
		logLevel int
	}
	flag.StringVar(&flags.confPath, "c", "config.yaml", "config file path")
	flag.IntVar(&flags.logLevel, "l", 0, "log level, -1 debug, 0 info ...")
	flag.Parse()

	logx.SetLevel(flags.logLevel)

	pwd, _ := os.Getwd()
	logx.Debugf("current pwd is %s", pwd)

	conf, err := config.LoadConf(flags.confPath)
	if err != nil {
		logx.Fatal(err)
	}

	manager.Init(conf)

	for _, p := range conf.Proxies {
		if err := runOne(p); err != nil {
			logx.Fatal(err)
		}
	}

	logx.Info("Noone started")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
