package ss

import "github.com/zzzzer91/noone/internal/config"

func Run(p *config.Proxy) {
	conf := convertSsConf(p)
	go runTcp(conf)
	go runUdp(conf)
}
