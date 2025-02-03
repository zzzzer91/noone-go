package trojan

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
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

type trojanCtx struct {
	*pure.CommonCtx
	conf       *trojanConf
	ClientConn net.Conn
	Cmd        simplesocks.CmdType
}

func newTrojanCtx() *trojanCtx {
	return &trojanCtx{
		CommonCtx: &pure.CommonCtx{
			ClientBuf: make([]byte, 63*1024),
			RemoteBuf: make([]byte, 63*1024),
		},
	}
}

func (c *trojanCtx) reset() {
	c.CommonCtx.Reset()
	c.conf = nil
	c.Cmd = simplesocks.CmdTypeUnspecified
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
		c.ClientConn = conn
		go handleClientConn(c)
	}
}

func handleClientConn(c *trojanCtx) {
	defer trojanCtxPool.Put(c)
	defer c.reset()
	shouldResponseHTTP := false
	defer func() {
		if shouldResponseHTTP {
			_, _ = c.ClientConn.Write([]byte(fallbackHTTPBody))
		}
	}()

	logx.Debug("TCP accept " + c.ClientConn.RemoteAddr().String())

	offset := 0
	for offset <= simplesocks.MinBufferLength {
		n, err := c.ClientConn.Read(c.ClientBuf[offset:])
		if err != nil {
			logx.Error(err)
			shouldResponseHTTP = true
			return
		}
		offset += n
	}
	c.ClientBufLen += offset
	if !bytes.Equal(c.ClientBuf[:simplesocks.PasswordLength], c.conf.hexPassword) {
		logx.Error("password not equal")
		shouldResponseHTTP = true
		return
	}
	c.ClientBufIdx += simplesocks.PasswordLength
	c.ClientBufIdx += len(simplesocks.Crlf)
	cmd := simplesocks.CmdType(c.ClientBuf[c.ClientBufIdx])
	c.ClientBufIdx++
	if !cmd.IsValid() {
		logx.Error("cmd is invalid")
		return
	}
	c.Cmd = cmd

	var t pure.Transporter
	if cmd == simplesocks.CmdTypeTCP {
		domain, remoteAddr, headerOffset, err := simplesocks.ParseHeader(cmd.NetWork(), c.ClientBuf[c.ClientBufIdx:])
		if err != nil {
			logx.Error(err)
			return
		}
		c.ClientBufIdx += headerOffset
		c.ClientBufIdx += len(simplesocks.Crlf)
		c.RemoteDomain = domain
		c.RemoteAddr = remoteAddr
		if c.RemoteDomain != "" {
			c.Info = fmt.Sprintf("%s (%s)", c.RemoteDomain, c.RemoteAddr.String())
		} else {
			c.Info = c.RemoteAddr.String()
		}

		logx.Debug("Connecting " + c.Info)
		conn, err := net.DialTimeout(pure.NetworkTypeTCP, c.RemoteAddr.String(), time.Second*5)
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
		logx.Info("Connected " + c.Info)
		t = pure.NewTCPConn(c.CommonCtx, conn)
	} else {
		conn, err := net.ListenUDP(pure.NetworkTypeUDP, nil)
		if err != nil {
			logx.Error(err)
			return
		}
		t = pure.NewUDPConn(c.CommonCtx, conn)
		logx.Info("Created udp pair: " + c.Info)
	}

	c.loop(t)

	logx.Debug(c.Info + " tunnel closed")
}

func (c *trojanCtx) loop(remoter pure.Transporter) {
	done := make(chan struct{})

	go func() {
		for {
			if err := remoter.Read(); err != nil {
				if !errors.Is(err, io.EOF) {
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
		if err := remoter.Write(); err != nil {
			logx.Error(c.Info + " writeRemote err: " + err.Error())
			break
		}
		if err := c.ReadClient(); err != nil {
			if !errors.Is(err, io.EOF) {
				logx.Error(c.Info + " readClient err: " + err.Error())
			}
			break
		}
	}
	remoter.Close()
	<-done
}

func (c *trojanCtx) ReadClient() error {
	n, err := c.ClientConn.Read(c.ClientBuf[c.ClientBufLen:])
	if err != nil {
		return err
	}
	c.ClientBufLen += n
	return nil
}

func (c *trojanCtx) WriteClient() error {
	if c.Cmd == simplesocks.CmdTypeTCP {
		for c.RemoteBufIdx < c.RemoteBufLen {
			n, err := c.ClientConn.Write(c.RemoteBuf[c.RemoteBufIdx:c.RemoteBufLen])
			if err != nil {
				return err
			}
			c.RemoteBufIdx += n
		}
	} else {
		for c.RemoteBufIdx < c.RemoteBufLen {
			header := simplesocks.BuildHeader(c.RemoteAddr.String())
			data := c.RemoteBuf[c.RemoteBufIdx:c.RemoteBufLen]
			header = binary.BigEndian.AppendUint16(header, uint16(len(data)))
			header = append(header, simplesocks.Crlf...)
			_, err := c.ClientConn.Write(append(header, data...))
			if err != nil {
				return err
			}
			c.RemoteBufIdx += len(data)
		}
	}
	c.RemoteBufIdx = 0
	c.RemoteBufLen = 0
	return nil
}
