package trojan

import (
	"encoding/binary"
	"errors"
	"net"
	"time"

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
		network: "udp",
	}
}

func (c *UDPConn) Read() error {
	s := c.ctx.RemoteDomain
	if s == "" {
		s = c.ctx.RemoteAddr.String()
	}
	offset := simplesocks.BuildUDPHeader(s, c.ctx.RemoteBuf)

	c.conn.SetReadDeadline(time.Now().Add(time.Second * 10))
	n, addr, err := c.conn.ReadFrom(c.ctx.RemoteBuf[offset:])
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(c.ctx.RemoteBuf[offset-2-len(simplesocks.Crlf):], uint16(n))

	if addr.String() != c.ctx.RemoteAddr.String() {
		return errors.New("the sent address is not equal to the received address")
	}

	c.ctx.RemoteBufLen += offset + n
	return nil
}

func (c *UDPConn) Write() error {
	_, err := c.conn.WriteTo(c.ctx.ClientBuf[c.ctx.ClientBufIdx:c.ctx.ClientBufLen], c.ctx.RemoteAddr)
	if err != nil {
		return err
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
