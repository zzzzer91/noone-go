package transport

import (
	"net"
	"noone/crypto"
)

type Ctx struct {
	Stage        int
	RemoteDomain string
	RemotePort   int
	ClientAddr   net.Addr
	RemoteAddr   net.Addr
	Encrypter    crypto.Encrypter
	Decrypter    crypto.Decrypter
}

func NewCtx() Ctx {
	return Ctx{
		Stage: StageInit,
	}
}

func (c *Ctx) Reset() {
	c.Stage = StageInit
	c.RemoteDomain = ""
	c.RemotePort = 0
	c.ClientAddr = nil
	c.RemoteAddr = nil
	c.Encrypter = nil
	c.Decrypter = nil
}
