package udp

import (
	"net"
	"noone/app/transport"
)

type ctx struct {
	transport.Ctx
	lClient *net.UDPConn
	lRemote *net.UDPConn
}
