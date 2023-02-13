package tcp

import (
	"errors"
	"fmt"
	"io"
	"net"
	"noone/app/crypto/aes"
	"noone/app/transport"
	"time"

	"github.com/sirupsen/logrus"
)

type ctx struct {
	transport.Ctx
	clientConn   *net.TCPConn
	remoteConn   *net.TCPConn
	clientBuf    []byte
	clientBufLen int
	clientBufIdx int // 已用数据偏移
	remoteBuf    []byte
	remoteBufLen int
	remoteBufIdx int
}

func NewCtx() *ctx {
	return &ctx{
		Ctx: transport.Ctx{
			Network: "tcp",
		},
		clientBuf: make([]byte, clientBufCapacity),
		remoteBuf: make([]byte, remoteBufCapacity),
	}
}

func (c *ctx) reset() {
	c.Ctx.Reset()
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

func (c *ctx) readClient() error {
	n, err := c.clientConn.Read(c.clientBuf)
	if err != nil {
		return err
	}
	c.clientBufIdx = 0
	c.clientBufLen = n
	if c.Decrypter == nil {
		if n < aes.IvLen {
			return errors.New("IV length is invaild")
		}
		c.Decrypter = aes.NewCtrDecrypter(c.UserInfo.Key, c.clientBuf[:aes.IvLen])
		c.clientBufIdx += aes.IvLen
		if c.clientBufIdx == c.clientBufLen {
			return nil
		}
	}
	// Decrypt 和 Encrypt 的 dst 和 src 内存区域允许重叠，但是有条件：
	// 那就是 &dst[0] 和 &src[0] 必须相同
	tmp := c.clientBuf[c.clientBufIdx:c.clientBufLen]
	c.Decrypter.Decrypt(tmp, tmp)
	return nil
}

func (c *ctx) writeRemote() error {
	for c.clientBufIdx < c.clientBufLen {
		n, err := c.remoteConn.Write(c.clientBuf[c.clientBufIdx:c.clientBufLen])
		if err != nil {
			return err
		}
		c.clientBufIdx += n
	}
	return nil
}

func (c *ctx) readRemote() error {
	offset := 0
	if c.Encrypter == nil {
		// 随机生成 IV，然后发送给客户端
		if err := aes.GenRandomIv(c.remoteBuf[:aes.IvLen]); err != nil {
			return err
		}
		c.Encrypter = aes.NewCtrEncrypter(c.UserInfo.Key, c.remoteBuf[:aes.IvLen])
		offset = aes.IvLen
	}
	n, err := c.remoteConn.Read(c.remoteBuf[offset:])
	if err != nil {
		return err
	}
	c.remoteBufIdx = 0
	c.remoteBufLen = n + offset
	tmp := c.remoteBuf[offset:c.remoteBufLen]
	c.Encrypter.Encrypt(tmp, tmp)
	return nil
}

func (c *ctx) writeClient() error {
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

func (c *ctx) handleStageInit() error {
	if err := c.readClient(); err != nil {
		return err
	}
	if c.clientBufIdx == c.clientBufLen { // 可能第一次只发了Decrypter过来，这时要再读一次读到header
		if err := c.readClient(); err != nil {
			return err
		}
	}
	offset, err := c.ParseHeader(c.clientBuf[c.clientBufIdx:c.clientBufLen])
	if err != nil {
		return err
	}
	c.clientBufIdx += offset

	if c.RemoteDomain != "" {
		c.Info = fmt.Sprintf("%s:%d (%s)", c.RemoteDomain, c.RemotePort, c.RemoteAddr.String())
	} else {
		c.Info = c.RemoteAddr.String()
	}

	c.Stage = transport.StageHandShake
	return nil
}

func (c *ctx) handleStageHandShake() error {
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
	c.Stage = transport.StageStream
	return nil
}

func (c *ctx) handleStageStream() error {
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
	c.Stage = transport.StageDestroyed
	// 暂时忽略 stream 阶段出现的错误
	return nil
}
