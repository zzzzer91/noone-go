package pure

import (
	"net"
)

type TCPConn struct {
	ctx     *CommonCtx
	conn    net.Conn
	network string
}

func NewTCPConn(commonCtx *CommonCtx, conn net.Conn) *TCPConn {
	return &TCPConn{
		ctx:     commonCtx,
		conn:    conn,
		network: NetworkTypeTCP,
	}
}

func (c *TCPConn) Read() error {
	n, err := c.conn.Read(c.ctx.RemoteBuf[c.ctx.RemoteBufLen:])
	if err != nil {
		return err
	}
	c.ctx.RemoteBufLen += n
	return nil
}

func (c *TCPConn) Write() error {
	for c.ctx.ClientBufIdx < c.ctx.ClientBufLen {
		n, err := c.conn.Write(c.ctx.ClientBuf[c.ctx.ClientBufIdx:c.ctx.ClientBufLen])
		if err != nil {
			return err
		}
		c.ctx.ClientBufIdx += n
	}
	c.ctx.ClientBufIdx = 0
	c.ctx.ClientBufLen = 0
	return nil
}

func (c *TCPConn) Close() {
	_ = c.conn.(*net.TCPConn).CloseWrite()
}

func (c *TCPConn) Network() string {
	return c.network
}
