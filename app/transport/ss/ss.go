package ss

import "noone/app/config"

func Run(p *config.Proxy) {
	conf := convertSsConf(p)
	go runTcp(conf)
	go runUdp(conf)
}
