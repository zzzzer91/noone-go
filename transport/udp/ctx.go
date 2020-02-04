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

func newCtx() *ctx {
	return &ctx{
		Ctx: transport.NewCtx("udp"),
	}
}
