package ss

import (
	"noone/app/transport/ss/tcp"
	"noone/app/transport/ss/udp"
	"noone/app/user"
)

func Run(u *user.User) {
	go tcp.Run(u)
	go udp.Run(u)
}
