package udp

import (
	"net"
	"noone/transport"
)

type ctx struct {
	transport.Ctx
	lClient *net.UDPConn
	lRemote *net.UDPConn
}
