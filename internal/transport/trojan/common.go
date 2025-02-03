package trojan

import (
	"net"
)

type CommonCtx struct {
	RemoteDomain string
	Info         string
	ClientAddr   net.Addr
	RemoteAddr   net.Addr
	ClientBuf    []byte
	ClientBufIdx int
	ClientBufLen int
	RemoteBuf    []byte
	RemoteBufIdx int
	RemoteBufLen int
}

func (c *CommonCtx) Reset() {
	// some fields don't need reset, e.g., network
	c.RemoteDomain = ""
	c.Info = ""
	c.ClientAddr = nil
	c.RemoteAddr = nil
	c.ClientBufLen = 0
	c.ClientBufIdx = 0
	c.RemoteBufLen = 0
	c.RemoteBufIdx = 0
}
