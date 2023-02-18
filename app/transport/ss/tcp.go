package ss

import (
	"errors"
	"fmt"
	"io"
	"net"
	"noone/app/crypto/aes"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
)

type tcpCtx struct {
	ssCtx
	clientConn   *net.TCPConn
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

func (c *tcpCtx) readClient() error {
	n, err := c.clientConn.Read(c.clientBuf)
	if err != nil {
		return err
	}
	c.clientBufIdx = 0
	c.clientBufLen = n
	if c.decrypter == nil {
		if n < aes.IvLen {
			return errors.New("IV length is invaild")
		}
		c.decrypter = aes.NewCtrDecrypter(c.conf.Key, c.clientBuf[:aes.IvLen])
		c.clientBufIdx += aes.IvLen
		if c.clientBufIdx == c.clientBufLen {
			return nil
		}
	}
	tmp := c.clientBuf[c.clientBufIdx:c.clientBufLen]
	c.decrypter.Decrypt(tmp, tmp)
	return nil
}

func (c *tcpCtx) writeRemote() error {
	for c.clientBufIdx < c.clientBufLen {
		n, err := c.remoteConn.Write(c.clientBuf[c.clientBufIdx:c.clientBufLen])
		if err != nil {
			return err
		}
		c.clientBufIdx += n
	}
	return nil
}

func (c *tcpCtx) readRemote() error {
	offset := 0
	if c.encrypter == nil {
		// 随机生成 IV，然后发送给客户端
		if err := aes.GenRandomIv(c.remoteBuf[:aes.IvLen]); err != nil {
			return err
		}
		c.encrypter = aes.NewCtrEncrypter(c.conf.Key, c.remoteBuf[:aes.IvLen])
		offset = aes.IvLen
	}
	n, err := c.remoteConn.Read(c.remoteBuf[offset:])
	if err != nil {
		return err
	}
	c.remoteBufIdx = 0
	c.remoteBufLen = n + offset
	tmp := c.remoteBuf[offset:c.remoteBufLen]
	c.encrypter.Encrypt(tmp, tmp)
	return nil
}

func (c *tcpCtx) writeClient() error {
	// 发送缓冲区可能满，这个时候要不停写，直到写完
	for c.remoteBufIdx < c.remoteBufLen {
		n, err := c.clientConn.Write(c.remoteBuf[c.remoteBufIdx:c.remoteBufLen])
		if err != nil {
			return err
		}
		c.remoteBufIdx += n
	}
	return nil
}

func (c *tcpCtx) handleStageInit() error {
	if err := c.readClient(); err != nil {
		return err
	}
	if c.clientBufIdx == c.clientBufLen { // 可能第一次只发了Decrypter过来，这时要再读一次读到header
		if err := c.readClient(); err != nil {
			return err
		}
	}
	offset, err := c.parseHeader(c.clientBuf[c.clientBufIdx:c.clientBufLen])
	if err != nil {
		return err
	}
	c.clientBufIdx += offset

	if c.remoteDomain != "" {
		c.info = fmt.Sprintf("%s:%d (%s)", c.remoteDomain, c.remotePort, c.remoteAddr.String())
	} else {
		c.info = c.remoteAddr.String()
	}

	return nil
}

func (c *tcpCtx) handleStageHandShake() error {
	logrus.Debug("Connecting " + c.info)
	conn, err := net.DialTimeout("tcp", c.remoteAddr.(*net.TCPAddr).String(), time.Second*5)
	if err != nil {
		return errors.New("Connect " + c.info + " error: " + err.Error())
	}
	c.remoteConn = conn.(*net.TCPConn)
	err = c.remoteConn.SetKeepAlive(true)
	if err != nil {
		return err
	}
	logrus.Info("Connected " + c.info)
	return nil
}

func (c *tcpCtx) handleStageStream() error {
	done := make(chan struct{})

	go func() {
		for {
			if err := c.readRemote(); err != nil {
				if err != io.EOF {
					logrus.Error(c.info + " readRemote err: " + err.Error())
				}
				break
			}
			if err := c.writeClient(); err != nil {
				logrus.Error(c.info + " writeClient err: " + err.Error())
				break
			}
		}
		_ = c.clientConn.CloseWrite()
		close(done)
	}()

	for {
		if err := c.writeRemote(); err != nil {
			logrus.Error(c.info + " writeRemote err: " + err.Error())
			break
		}
		if err := c.readClient(); err != nil {
			if err != io.EOF {
				logrus.Error(c.info + " readClient err: " + err.Error())
			}
			break
		}
	}
	_ = c.remoteConn.CloseWrite()
	<-done
	logrus.Debug(c.info + " tunnel closed")
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
		c.clientAddr = conn.RemoteAddr()
		c.clientConn = conn
		c.conf = conf

		go handleTcpClientConn(c)
	}
}

func handleTcpClientConn(c *tcpCtx) {
	defer tcpCtxPool.Put(c)
	defer c.reset()

	logrus.Debug("TCP accept " + c.clientAddr.String())

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
