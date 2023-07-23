package trojan

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/zzzzer91/noone/internal/config"
	"github.com/zzzzer91/noone/internal/protocol/simplesocks"
	"github.com/zzzzer91/noone/internal/transport/pure"

	"github.com/zzzzer91/gopkg/logx"
)

func Run(p *config.Proxy) {
	conf := convertTrojanConf(p)
	go run(conf)
}

func run(conf *trojanConf) {
	tlsConf := generateTLSConfig(conf.cn, conf.alpn)
	l, err := tls.Listen("tcp", conf.addr, tlsConf)
	if err != nil {
		logx.Fatal(err)
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			logx.Error(err)
			continue
		}
		if err := conn.(*tls.Conn).NetConn().(*net.TCPConn).SetKeepAlive(true); err != nil {
			conn.Close()
			logx.Error(err)
			continue
		}
		c := trojanCtxPool.Get().(*trojanCtx)
		c.ClientAddr = conn.RemoteAddr()
		c.ClientConn = conn
		c.conf = conf
		go handleClientConn(c)
	}
}

func handleClientConn(c *trojanCtx) {
	defer trojanCtxPool.Put(c)
	defer c.reset()
	shouldResponseHttp := false
	defer func() {
		if shouldResponseHttp {
			c.ClientConn.Write([]byte(fallbackHttpBody))
		}
	}()

	logx.Debug("TCP accept " + c.ClientAddr.String())

	c.ClientBufIdx = 0
	c.ClientBufLen = 0
	offset := 0
	for c.ClientBufLen <= 66 {
		n, err := c.ClientConn.Read(c.ClientBuf[offset:])
		if err != nil {
			logx.Error(err)
			shouldResponseHttp = true
			return
		}
		offset += n
		c.ClientBufLen += n
	}
	if !bytes.Equal(c.ClientBuf[:56], c.conf.hexPassword) {
		logx.Error("password not equal")
		shouldResponseHttp = true
		return
	}
	c.ClientBufIdx += 58
	cmd := c.ClientBuf[c.ClientBufIdx]
	if cmd != commandTCP && cmd != commandUDP {
		logx.Error("cmd is invalid")
		return
	}
	c.ClientBufIdx += 1
	domain, remoteAddr, headerOffset, err := simplesocks.ParseHeader(c.Network, c.ClientBuf[c.ClientBufIdx:])
	if err != nil {
		logx.Error(err)
		return
	}
	c.ClientBufIdx += headerOffset + 2
	c.RemoteDomain = domain
	c.RemoteAddr = remoteAddr
	if c.RemoteDomain != "" {
		c.Info = fmt.Sprintf("%s (%s)", c.RemoteDomain, c.RemoteAddr.String())
	} else {
		c.Info = c.RemoteAddr.String()
	}

	logx.Debug("Connecting " + c.Info)
	conn, err := net.DialTimeout("tcp", c.RemoteAddr.(*net.TCPAddr).String(), time.Second*5)
	if err != nil {
		err = errors.New("Connect " + c.Info + " error: " + err.Error())
		logx.Error(err)
		return
	}
	err = conn.(*net.TCPConn).SetKeepAlive(true)
	if err != nil {
		logx.Error(err)
		return
	}
	c.RemoteConn = conn
	logx.Info("Connected " + c.Info)

	done := make(chan struct{})

	go func() {
		for {
			if err := c.ReadRemote(); err != nil {
				if err != io.EOF {
					logx.Error(c.Info + " readRemote err: " + err.Error())
				}
				break
			}
			if err := c.WriteClient(); err != nil {
				logx.Error(c.Info + " writeClient err: " + err.Error())
				break
			}
		}
		_ = c.ClientConn.(*tls.Conn).CloseWrite()
		close(done)
	}()

	for {
		if err := c.WriteRemote(); err != nil {
			logx.Error(c.Info + " writeRemote err: " + err.Error())
			break
		}
		if err := c.ReadClient(); err != nil {
			if err != io.EOF {
				logx.Error(c.Info + " readClient err: " + err.Error())
			}
			break
		}
	}
	_ = c.RemoteConn.(*net.TCPConn).CloseWrite()
	<-done
	logx.Debug(c.Info + " tunnel closed")
}

type trojanCtx struct {
	*pure.TcpCtx
	conf *trojanConf
}

func newTrojanCtx() *trojanCtx {
	return &trojanCtx{
		TcpCtx: pure.NewTcpCtx(),
	}
}

func (c *trojanCtx) reset() {
	c.TcpCtx.Reset()
	c.conf = nil
}
