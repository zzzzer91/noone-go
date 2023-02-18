package trojan

import (
	"crypto/tls"
	"net"
)

type tcpCtx struct {
	ssCtx
	clientConn   *tls.Conn
	remoteConn   *net.TCPConn
	clientBuf    []byte
	clientBufLen int
	clientBufIdx int
	remoteBuf    []byte
	remoteBufLen int
	remoteBufIdx int
}

func newTcpCtx() *tcpCtx {
	return &tcpCtx{
		ssCtx: ssCtx{
			network: "tcp",
		},
		clientBuf: make([]byte, tcpClientBufCapacity),
		remoteBuf: make([]byte, tcpRemoteBufCapacity),
	}
}

func (c *tcpCtx) reset() {
	c.ssCtx.reset()
	if c.clientConn != nil {
		_ = c.clientConn.Close()
		c.clientConn = nil
	}
	if c.remoteConn != nil {
		_ = c.remoteConn.Close()
		c.remoteConn = nil
	}
	c.clientBufLen = 0
	c.clientBufIdx = 0
	c.remoteBufLen = 0
	c.remoteBufIdx = 0
}
