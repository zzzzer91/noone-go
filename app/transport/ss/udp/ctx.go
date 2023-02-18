package udp

import (
	"net"
	"noone/app/transport/ss/common"
)

type ctx struct {
	common.Ctx
	lClient *net.UDPConn
	lRemote *net.UDPConn
}
