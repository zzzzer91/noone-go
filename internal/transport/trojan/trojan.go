package trojan

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/zzzzer91/gopkg/logx"
	"github.com/zzzzer91/noone/internal/config"
	"github.com/zzzzer91/noone/internal/protocol/simplesocks"
)

type trojanCtx struct {
	ctx        *CommonCtx
	conf       *trojanConf
	clientConn net.Conn
	cmd        simplesocks.CmdType
}

func newTrojanCtx() *trojanCtx {
	return &trojanCtx{
		ctx: &CommonCtx{
			ClientBuf: make([]byte, 16*1024),
			RemoteBuf: make([]byte, 16*1024),
		},
	}
}

func (c *trojanCtx) reset() {
	c.ctx.Reset()
	c.conf = nil
	c.cmd = simplesocks.CmdTypeUnspecified
}

func Run(p *config.Proxy) {
	conf := convertTrojanConf(p)
	go run(conf)
}

func run(conf *trojanConf) {
	tlsConf := generateTLSConfig(conf.cn, conf.alpn)
	tlsListener, err := tls.Listen("tcp", conf.addr, tlsConf)
	if err != nil {
		logx.Fatal(err)
	}
	defer tlsListener.Close()
	for {
		conn, err := tlsListener.Accept()
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
		c.conf = conf
		c.clientConn = conn
		go handleClientConn(c)
	}
}

func handleClientConn(c *trojanCtx) {
	defer trojanCtxPool.Put(c)
	defer c.reset()
	shouldResponseHTTP := false
	defer func() {
		if shouldResponseHTTP {
			_, _ = c.clientConn.Write([]byte(fallbackHTTPBody))
		}
	}()

	c.ctx.ClientAddr = c.clientConn.RemoteAddr()
	logx.Debug("accept connect: " + c.ctx.ClientAddr.String())

	offset := 0
	for offset <= simplesocks.MinClientHeaderLength {
		n, err := c.clientConn.Read(c.ctx.ClientBuf[offset:])
		if err != nil {
			logx.Error(err)
			shouldResponseHTTP = true
			return
		}
		offset += n
	}
	c.ctx.ClientBufLen += offset
	if !bytes.Equal(c.ctx.ClientBuf[:simplesocks.PasswordLength], c.conf.hexPassword) {
		logx.Error("password not equal")
		shouldResponseHTTP = true
		return
	}
	c.ctx.ClientBufIdx += simplesocks.PasswordLength
	c.ctx.ClientBufIdx += len(simplesocks.Crlf)
	cmd := simplesocks.CmdType(c.ctx.ClientBuf[c.ctx.ClientBufIdx])
	c.ctx.ClientBufIdx++
	if !cmd.IsValid() {
		logx.Error("cmd is invalid")
		return
	}
	c.cmd = cmd
	domain, remoteAddr, headerOffset, err := simplesocks.ParseHeader(cmd, c.ctx.ClientBuf[c.ctx.ClientBufIdx:])
	if err != nil {
		logx.Error(err)
		return
	}
	c.ctx.ClientBufIdx += headerOffset
	c.ctx.ClientBufIdx += len(simplesocks.Crlf)
	c.ctx.RemoteDomain = domain
	c.ctx.RemoteAddr = remoteAddr
	if c.ctx.RemoteDomain != "" {
		c.ctx.Info = fmt.Sprintf("[%s] %s -> %s (%s)", c.cmd.NetWork(), c.ctx.ClientAddr.String(), c.ctx.RemoteDomain, c.ctx.RemoteAddr.String())
	} else {
		c.ctx.Info = fmt.Sprintf("[%s] %s -> %s", c.cmd.NetWork(), c.ctx.ClientAddr.String(), c.ctx.RemoteAddr.String())
	}

	var remoter Transporter
	if cmd == simplesocks.CmdTypeTCP {
		logx.Debug(c.ctx.Info + " is connecting")
		conn, err := net.DialTimeout("tcp", c.ctx.RemoteAddr.String(), time.Second*5)
		if err != nil {
			err = errors.New(c.ctx.Info + " connect error: " + err.Error())
			logx.Error(err)
			return
		}
		err = conn.(*net.TCPConn).SetKeepAlive(true)
		if err != nil {
			logx.Error(err)
			return
		}
		logx.Info(c.ctx.Info + " connected")
		remoter = NewTCPConn(c.ctx, conn)
	} else {
		conn, err := net.ListenUDP("udp", nil)
		if err != nil {
			logx.Error(err)
			return
		}
		remoter = NewUDPConn(c.ctx, conn)
		logx.Info(c.ctx.Info + " udp pair created")
	}

	if err := remoter.Write(); err != nil {
		logx.Error(c.ctx.Info + " initialWriteRemote err: " + err.Error())
		return
	}

	c.loop(remoter)

	logx.Debug(c.ctx.Info + " tunnel closed")
}

func (c *trojanCtx) loop(remoter Transporter) {
	wg := sync.WaitGroup{}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			if err := remoter.Read(); err != nil {
				if !errors.Is(err, io.EOF) {
					logx.Error(c.ctx.Info + " readRemote err: " + err.Error())
				}
				break
			}
			if err := c.writeClient(); err != nil {
				logx.Error(c.ctx.Info + " writeClient err: " + err.Error())
				break
			}
		}
		c.clientConn.Close()
	}()

	for {
		if err := c.readClient(); err != nil {
			if !errors.Is(err, io.EOF) {
				logx.Error(c.ctx.Info + " readClient err: " + err.Error())
			}
			break
		}
		if err := remoter.Write(); err != nil {
			logx.Error(c.ctx.Info + " writeRemote err: " + err.Error())
			break
		}
	}
	remoter.Close()
	wg.Wait()
}

func (c *trojanCtx) readClient() error {
	if c.cmd == simplesocks.CmdTypeTCP {
		n, err := c.clientConn.Read(c.ctx.ClientBuf[c.ctx.ClientBufLen:])
		if err != nil {
			return err
		}
		c.ctx.ClientBufLen += n
	} else {
		_, err := c.clientConn.Read(c.ctx.ClientBuf[c.ctx.ClientBufLen:])
		if err != nil {
			return err
		}
		_, _, headerOffset, err := simplesocks.ParseHeader(simplesocks.CmdTypeUDP, c.ctx.ClientBuf[c.ctx.ClientBufIdx:])
		if err != nil {
			return err
		}
		c.ctx.ClientBufIdx += headerOffset
		bufLen := (int(c.ctx.ClientBuf[c.ctx.ClientBufIdx]) << 8) | int(c.ctx.ClientBuf[c.ctx.ClientBufIdx+1])
		c.ctx.ClientBufIdx += 2
		c.ctx.ClientBufIdx += len(simplesocks.Crlf)
		c.ctx.ClientBufLen = c.ctx.ClientBufIdx + bufLen
	}
	return nil
}

func (c *trojanCtx) writeClient() error {
	for c.ctx.RemoteBufIdx < c.ctx.RemoteBufLen {
		n, err := c.clientConn.Write(c.ctx.RemoteBuf[c.ctx.RemoteBufIdx:c.ctx.RemoteBufLen])
		if err != nil {
			return err
		}
		c.ctx.RemoteBufIdx += n
	}
	c.ctx.RemoteBufIdx = 0
	c.ctx.RemoteBufLen = 0
	return nil
}
