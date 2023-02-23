package pure

import (
	"net"
)

type TcpCtx struct {
	TransportCtx
	ClientConn net.Conn
	RemoteConn net.Conn
}

func NewTcpCtx() *TcpCtx {
	return &TcpCtx{
		TransportCtx: TransportCtx{
			Network:   "tcp",
			ClientBuf: make([]byte, TcpClientBufCapacity),
			RemoteBuf: make([]byte, TcpRemoteBufCapacity),
		},
	}
}

func (c *TcpCtx) Reset() {
	c.TransportCtx.Reset()
	if c.ClientConn != nil {
		_ = c.ClientConn.Close()
		c.ClientConn = nil
	}
	if c.RemoteConn != nil {
		_ = c.RemoteConn.Close()
		c.RemoteConn = nil
	}
}

func (c *TcpCtx) ReadClient() error {
	n, err := c.ClientConn.Read(c.ClientBuf[c.ClientBufLen:])
	if err != nil {
		return err
	}
	c.ClientBufLen += n
	return nil
}

func (c *TcpCtx) WriteRemote() error {
	for c.ClientBufIdx < c.ClientBufLen {
		n, err := c.RemoteConn.Write(c.ClientBuf[c.ClientBufIdx:c.ClientBufLen])
		if err != nil {
			return err
		}
		c.ClientBufIdx += n
	}
	c.ClientBufIdx = 0
	c.ClientBufLen = 0
	return nil
}

func (c *TcpCtx) ReadRemote() error {
	n, err := c.RemoteConn.Read(c.RemoteBuf[c.RemoteBufLen:])
	if err != nil {
		return err
	}
	c.RemoteBufLen += n
	return nil
}

func (c *TcpCtx) WriteClient() error {
	for c.RemoteBufIdx < c.RemoteBufLen {
		n, err := c.ClientConn.Write(c.RemoteBuf[c.RemoteBufIdx:c.RemoteBufLen])
		if err != nil {
			return err
		}
		c.RemoteBufIdx += n
	}
	c.RemoteBufIdx = 0
	c.RemoteBufLen = 0
	return nil
}
