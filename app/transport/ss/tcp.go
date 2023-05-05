package ss

import (
	"errors"
	"fmt"
	"io"
	"net"
	"noone/app/crypto"
	"noone/app/crypto/aes"
	"noone/app/protocol/simplesocks"
	"noone/app/transport/pure"
	"time"

	"github.com/zzzzer91/gopkg/logx"
)

func runTcp(conf *ssConf) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", conf.addr)
	if err != nil {
		logx.Fatal(err)
	}
	l, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		logx.Fatal(err)
	}
	for {
		conn, err := l.AcceptTCP()
		if err != nil {
			logx.Error(err)
			continue
		}
		if err := conn.SetKeepAlive(true); err != nil {
			conn.Close()
			logx.Error(err)
			continue
		}

		c := tcpCtxPool.Get().(*ssTcpCtx)
		c.ClientAddr = conn.RemoteAddr()
		c.ClientConn = conn
		c.conf = conf

		go handleTcpClientConn(c)
	}
}

func handleTcpClientConn(c *ssTcpCtx) {
	defer tcpCtxPool.Put(c)
	defer c.reset()

	logx.Debug("TCP accept " + c.ClientAddr.String())

	if err := c.handleStageInit(); err != nil {
		logx.Error(err)
		return
	}

	if err := c.handleStageHandShake(); err != nil {
		logx.Error(err)
		return
	}

	if err := c.handleStageStream(); err != nil {
		logx.Error(err)
		return
	}
}

type ssTcpCtx struct {
	*pure.TcpCtx
	encrypter crypto.Encrypter
	decrypter crypto.Decrypter
	conf      *ssConf
}

func newSsTcpCtx() *ssTcpCtx {
	return &ssTcpCtx{
		TcpCtx: pure.NewTcpCtx(),
	}
}

func (c *ssTcpCtx) reset() {
	c.TcpCtx.Reset()
	c.encrypter = nil
	c.decrypter = nil
	c.conf = nil
}

func (c *ssTcpCtx) handleStageInit() error {
	if err := c.ReadClient(); err != nil {
		return err
	}
	if c.ClientBufLen < aes.IvLen {
		return errors.New("IV length is invalid")
	}
	c.decrypter = aes.NewCtrDecrypter(c.conf.Key, c.ClientBuf[:aes.IvLen])
	c.ClientBufIdx += aes.IvLen
	if c.ClientBufIdx == c.ClientBufLen { // 可能第一次只发了Decrypter过来，这时要再读一次读到header
		c.ClientBufIdx = 0
		c.ClientBufLen = 0
		if err := c.ReadClient(); err != nil {
			return err
		}
	}
	c.decrypter.Decrypt(c.ClientBuf[c.ClientBufIdx:c.ClientBufLen], c.ClientBuf[c.ClientBufIdx:c.ClientBufLen])
	domain, remoteAddr, offset, err := simplesocks.ParseHeader(c.Network, c.ClientBuf[c.ClientBufIdx:c.ClientBufLen])
	if err != nil {
		return err
	}
	c.ClientBufIdx += offset
	c.RemoteDomain = domain
	c.RemoteAddr = remoteAddr

	if c.RemoteDomain != "" {
		c.Info = fmt.Sprintf("%s:%d (%s)", c.RemoteDomain, c.RemotePort, c.RemoteAddr.String())
	} else {
		c.Info = c.RemoteAddr.String()
	}

	return nil
}

func (c *ssTcpCtx) handleStageHandShake() error {
	logx.Debug("Connecting " + c.Info)
	conn, err := net.DialTimeout("tcp", c.RemoteAddr.(*net.TCPAddr).String(), time.Second*5)
	if err != nil {
		return errors.New("Connect " + c.Info + " error: " + err.Error())
	}
	err = conn.(*net.TCPConn).SetKeepAlive(true)
	if err != nil {
		return err
	}
	c.RemoteConn = conn
	logx.Info("Connected " + c.Info)
	return nil
}

func (c *ssTcpCtx) handleStageStream() error {
	done := make(chan struct{})

	go func() {
		for {
			offset := 0
			if c.encrypter == nil {
				// 随机生成 IV，然后发送给客户端
				if err := aes.GenRandomIv(c.RemoteBuf[:aes.IvLen]); err != nil {
					logx.Error(err)
					return
				}
				c.encrypter = aes.NewCtrEncrypter(c.conf.Key, c.RemoteBuf[:aes.IvLen])
				offset += aes.IvLen
			}
			c.RemoteBufLen += offset
			if err := c.ReadRemote(); err != nil {
				if err != io.EOF {
					logx.Error(c.Info + " readRemote err: " + err.Error())
				}
				break
			}
			c.encrypter.Encrypt(c.RemoteBuf[offset:c.RemoteBufLen], c.RemoteBuf[offset:c.RemoteBufLen])
			if err := c.WriteClient(); err != nil {
				logx.Error(c.Info + " writeClient err: " + err.Error())
				break
			}
		}
		_ = c.ClientConn.(*net.TCPConn).CloseWrite()
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
		c.decrypter.Decrypt(c.ClientBuf[c.ClientBufIdx:c.ClientBufLen], c.ClientBuf[c.ClientBufIdx:c.ClientBufLen])
	}
	_ = c.RemoteConn.(*net.TCPConn).CloseWrite()
	<-done
	logx.Debug(c.Info + " tunnel closed")
	return nil
}
