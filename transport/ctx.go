package transport

import "noone/crypto"

type Ctx struct {
	Stage      int
	ClientAddr string
	RemoteAddr string
	Encrypter  crypto.Encrypter
	Decrypter  crypto.Decrypter
}

func NewCtx() Ctx {
	return Ctx{
		Stage: StageInit,
	}
}

func (c *Ctx) Reset() {
	c.Stage = StageInit
	c.ClientAddr = ""
	c.RemoteAddr = ""
	c.Encrypter = nil
	c.Decrypter = nil
}
