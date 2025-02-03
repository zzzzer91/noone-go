package pure

import (
	"errors"
	"fmt"
	"net"

	"github.com/zzzzer91/noone/internal/protocol/simplesocks"
)

type UDPConn struct {
	ctx     *CommonCtx
	conn    net.PacketConn
	network string
}

func NewUDPConn(commonCtx *CommonCtx, conn net.PacketConn) *UDPConn {
	return &UDPConn{
		ctx:     commonCtx,
		conn:    conn,
		network: NetworkTypeUDP,
	}
}

func (c *UDPConn) Read() error {
	n, addr, err := c.conn.ReadFrom(c.ctx.RemoteBuf[c.ctx.RemoteBufLen:])
	if err != nil {
		return err
	}

	if addr.String() != c.ctx.RemoteAddr.String() {
		return errors.New("the sent address is not equal to the received address")
	}
	c.ctx.RemoteBufLen += n
	return nil
}

func (c *UDPConn) Write() error {
	for c.ctx.ClientBufIdx < c.ctx.ClientBufLen {
		domain, remoteAddr, headerOffset, err := simplesocks.ParseHeader(c.network, c.ctx.ClientBuf[c.ctx.ClientBufIdx:])
		if err != nil {
			return err
		}
		c.ctx.ClientBufIdx += headerOffset
		c.ctx.RemoteDomain = domain
		c.ctx.RemoteAddr = remoteAddr
		if c.ctx.RemoteDomain != "" {
			c.ctx.Info = fmt.Sprintf("%s (%s)", c.ctx.RemoteDomain, c.ctx.RemoteAddr.String())
		} else {
			c.ctx.Info = c.ctx.RemoteAddr.String()
		}
		if string(c.ctx.ClientBuf[c.ctx.ClientBufIdx:c.ctx.ClientBufIdx+2]) == simplesocks.Crlf {
			break
		}
		bufLen := (int(c.ctx.ClientBuf[c.ctx.ClientBufIdx]) << 8) | int(c.ctx.ClientBuf[c.ctx.ClientBufIdx+1])
		c.ctx.ClientBufIdx += 2
		c.ctx.ClientBufIdx += len(simplesocks.Crlf)

		n, err := c.conn.WriteTo(c.ctx.ClientBuf[c.ctx.ClientBufIdx:c.ctx.ClientBufIdx+bufLen], c.ctx.RemoteAddr)
		if err != nil {
			return err
		}
		c.ctx.ClientBufIdx += n
	}
	c.ctx.ClientBufIdx = 0
	c.ctx.ClientBufLen = 0
	return nil
}

func (c *UDPConn) Close() {
	c.conn.Close()
}

func (c *UDPConn) Network() string {
	return c.network
}
