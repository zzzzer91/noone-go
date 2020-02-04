package transport

import (
	"net"
	"noone/crypto"
)

type Ctx struct {
	Network      string
	Stage        int
	RemoteDomain string
	RemotePort   int
	ClientAddr   net.Addr
	RemoteAddr   net.Addr
	Encrypter    crypto.Encrypter
	Decrypter    crypto.Decrypter
}

func NewCtx(network string) Ctx {
	return Ctx{
		Network: network,
		Stage:   StageInit,
	}
}

func (c *Ctx) Reset() {
	c.Network = ""
	c.Stage = StageInit
	c.RemoteDomain = ""
	c.RemotePort = 0
	c.ClientAddr = nil
	c.RemoteAddr = nil
	c.Encrypter = nil
	c.Decrypter = nil
}
