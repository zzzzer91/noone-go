package ss

import (
	"errors"
	"fmt"
	"io"
	"net"
	"noone/app/crypto"
	"noone/app/crypto/aes"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
)

type tcpCtx struct {
	SsCtx
	clientConn *net.TCPConn
	remoteConn *net.TCPConn
	encrypter  crypto.Encrypter
	decrypter  crypto.Decrypter
	conf       *ssConf
}

func newTcpCtx() *tcpCtx {
	return &tcpCtx{
		SsCtx: SsCtx{
			Network:   "tcp",
			ClientBuf: make([]byte, tcpClientBufCapacity),
			RemoteBuf: make([]byte, tcpRemoteBufCapacity),
		},
	}
}

func (c *tcpCtx) reset() {
	c.SsCtx.Reset()
	if c.clientConn != nil {
		_ = c.clientConn.Close()
		c.clientConn = nil
	}
	if c.remoteConn != nil {
		_ = c.remoteConn.Close()
		c.remoteConn = nil
	}
	c.encrypter = nil
	c.decrypter = nil
	c.conf = nil
}

func (c *tcpCtx) readClient() error {
	n, err := c.clientConn.Read(c.ClientBuf)
	if err != nil {
		return err
	}
	c.ClientBufIdx = 0
	c.ClientBufLen = n
	if c.decrypter == nil {
		if n < aes.IvLen {
			return errors.New("IV length is invaild")
		}
		c.decrypter = aes.NewCtrDecrypter(c.conf.Key, c.ClientBuf[:aes.IvLen])
		c.ClientBufIdx += aes.IvLen
		if c.ClientBufIdx == c.ClientBufLen {
			return nil
		}
	}
	tmp := c.ClientBuf[c.ClientBufIdx:c.ClientBufLen]
	c.decrypter.Decrypt(tmp, tmp)
	return nil
}

func (c *tcpCtx) writeRemote() error {
	for c.ClientBufIdx < c.ClientBufLen {
		n, err := c.remoteConn.Write(c.ClientBuf[c.ClientBufIdx:c.ClientBufLen])
		if err != nil {
			return err
		}
		c.ClientBufIdx += n
	}
	return nil
}

func (c *tcpCtx) readRemote() error {
	offset := 0
	if c.encrypter == nil {
		// 随机生成 IV，然后发送给客户端
		if err := aes.GenRandomIv(c.RemoteBuf[:aes.IvLen]); err != nil {
			return err
		}
		c.encrypter = aes.NewCtrEncrypter(c.conf.Key, c.RemoteBuf[:aes.IvLen])
		offset = aes.IvLen
	}
	n, err := c.remoteConn.Read(c.RemoteBuf[offset:])
	if err != nil {
		return err
	}
	c.RemoteBufIdx = 0
	c.RemoteBufLen = n + offset
	tmp := c.RemoteBuf[offset:c.RemoteBufLen]
	c.encrypter.Encrypt(tmp, tmp)
	return nil
}

func (c *tcpCtx) writeClient() error {
	// 发送缓冲区可能满，这个时候要不停写，直到写完
	for c.RemoteBufIdx < c.RemoteBufLen {
		n, err := c.clientConn.Write(c.RemoteBuf[c.RemoteBufIdx:c.RemoteBufLen])
		if err != nil {
			return err
		}
		c.RemoteBufIdx += n
	}
	return nil
}

func (c *tcpCtx) handleStageInit() error {
	if err := c.readClient(); err != nil {
		return err
	}
	if c.ClientBufIdx == c.ClientBufLen { // 可能第一次只发了Decrypter过来，这时要再读一次读到header
		if err := c.readClient(); err != nil {
			return err
		}
	}
	offset, err := c.ParseHeader(c.ClientBuf[c.ClientBufIdx:c.ClientBufLen])
	if err != nil {
		return err
	}
	c.ClientBufIdx += offset

	if c.RemoteDomain != "" {
		c.Info = fmt.Sprintf("%s:%d (%s)", c.RemoteDomain, c.RemotePort, c.RemoteAddr.String())
	} else {
		c.Info = c.RemoteAddr.String()
	}

	return nil
}

func (c *tcpCtx) handleStageHandShake() error {
	logrus.Debug("Connecting " + c.Info)
	conn, err := net.DialTimeout("tcp", c.RemoteAddr.(*net.TCPAddr).String(), time.Second*5)
	if err != nil {
		return errors.New("Connect " + c.Info + " error: " + err.Error())
	}
	c.remoteConn = conn.(*net.TCPConn)
	err = c.remoteConn.SetKeepAlive(true)
	if err != nil {
		return err
	}
	logrus.Info("Connected " + c.Info)
	return nil
}

func (c *tcpCtx) handleStageStream() error {
	done := make(chan struct{})

	go func() {
		for {
			if err := c.readRemote(); err != nil {
				if err != io.EOF {
					logrus.Error(c.Info + " readRemote err: " + err.Error())
				}
				break
			}
			if err := c.writeClient(); err != nil {
				logrus.Error(c.Info + " writeClient err: " + err.Error())
				break
			}
		}
		_ = c.clientConn.CloseWrite()
		close(done)
	}()

	for {
		if err := c.writeRemote(); err != nil {
			logrus.Error(c.Info + " writeRemote err: " + err.Error())
			break
		}
		if err := c.readClient(); err != nil {
			if err != io.EOF {
				logrus.Error(c.Info + " readClient err: " + err.Error())
			}
			break
		}
	}
	_ = c.remoteConn.CloseWrite()
	<-done
	logrus.Debug(c.Info + " tunnel closed")
	return nil
}

func runTcp(conf *ssConf) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", conf.server+":"+strconv.Itoa(conf.port))
	if err != nil {
		logrus.Fatal(err)
	}
	l, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		logrus.Fatal(err)
	}
	for {
		conn, err := l.AcceptTCP()
		if err != nil {
			logrus.Error(err)
			continue
		}
		if err := conn.SetKeepAlive(true); err != nil {
			logrus.Error(err)
			return
		}

		c := tcpCtxPool.Get().(*tcpCtx)
		c.ClientAddr = conn.RemoteAddr()
		c.clientConn = conn
		c.conf = conf

		go handleTcpClientConn(c)
	}
}

func handleTcpClientConn(c *tcpCtx) {
	defer tcpCtxPool.Put(c)
	defer c.reset()

	logrus.Debug("TCP accept " + c.ClientAddr.String())

	if err := c.handleStageInit(); err != nil {
		logrus.Error(err)
		return
	}

	if err := c.handleStageHandShake(); err != nil {
		logrus.Error(err)
		return
	}

	if err := c.handleStageStream(); err != nil {
		logrus.Error(err)
		return
	}
}
