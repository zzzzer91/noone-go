package transport

import "noone/crypto"

type Ctx struct {
	Network    string
	Stage      int
	ClientAddr string
	RemoteAddr string
	Encrypter  crypto.Encrypter
	Decrypter  crypto.Decrypter
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
	c.ClientAddr = ""
	c.RemoteAddr = ""
	c.Encrypter = nil
	c.Decrypter = nil
}
