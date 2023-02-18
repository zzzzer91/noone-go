package ss

import (
	"noone/app/manager"
	"noone/app/transport/ss/tcp"
	"noone/app/transport/ss/udp"
)

func Run(p *manager.Proxy) {
	go tcp.Run(p)
	go udp.Run(p)
}
