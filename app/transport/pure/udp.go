package pure

import (
	"net"
)

type UdpCtx struct {
	*TransportCtx
	LClient net.Conn
	LRemote net.Conn
}

func NewUdpCtx() *UdpCtx {
	return &UdpCtx{
		TransportCtx: &TransportCtx{
			Network:   "udp",
			ClientBuf: make([]byte, UdpClientBufCapacity),
			RemoteBuf: make([]byte, UdpRemoteBufCapacity),
		},
	}
}

func (c *UdpCtx) Reset() {
	c.TransportCtx.Reset()
	c.LClient = nil
	c.LRemote = nil
}
