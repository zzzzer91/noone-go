package tcp

import (
	"crypto/rand"
	"errors"
	"github.com/kataras/golog"
	"io"
	"net"
	"noone/conf"
	"noone/crypto"
	"noone/crypto/aes"
	"noone/transport"
	"time"
)

const (
	StreamTimeout = 1 * time.Minute
)

type ctx struct {
	Stage        int
	Addr         string
	Encrypter    crypto.Encrypter
	Decrypter    crypto.Decrypter
	clientConn   *net.TCPConn
	remoteConn   *net.TCPConn
	clientBuf    []byte
	clientBufLen int
	remoteBuf    []byte
	remoteBufLen int
}

func newCtx() *ctx {
	return &ctx{
		Stage:     transport.StageInit,
		clientBuf: make([]byte, transport.ClientBufCapacity),
		remoteBuf: make([]byte, transport.RemoteBufCapacity),
	}
}

func (c *ctx) reset() {
	c.Stage = transport.StageInit
	c.Addr = ""
	c.Encrypter = nil
	c.Decrypter = nil
	c.clientBufLen = 0
	c.remoteBufLen = 0
	if c.clientConn != nil {
		_ = c.clientConn.Close()
		c.clientConn = nil
	}
	if c.remoteConn != nil {
		_ = c.remoteConn.Close()
		c.remoteConn = nil
	}
}

func (c *ctx) readClient() error {
	n, err := c.clientConn.Read(c.clientBuf)
	if err != nil {
		return err
	}
	c.clientBufLen = n
	if c.Decrypter == nil {
		if n < aes.IvLen {
			return errors.New("IV长度不合法")
		}
		c.Decrypter = aes.NewCtrDecrypter(crypto.Kdf(conf.S.Password, aes.IvLen), c.clientBuf[:aes.IvLen])
		c.clientBufLen -= aes.IvLen
		if c.clientBufLen == 0 {
			return nil
		}
		copy(c.clientBuf, c.clientBuf[aes.IvLen:n])
	}
	// Decrypt 和 Encrypt 的 dst 和 src 内存区域允许重叠，但是有条件：
	// 那就是 &dst[0] 和 &src[0] 必须相同
	c.Decrypter.Decrypt(c.clientBuf, c.clientBuf[:c.clientBufLen])
	return nil
}

func (c *ctx) writeRemote() error {
	if c.clientBufLen > 0 {
		n, err := c.remoteConn.Write(c.clientBuf[:c.clientBufLen])
		if err != nil {
			return err
		}
		c.clientBufLen -= n
	}
	return nil
}

func (c *ctx) readRemote() error {
	offset := 0
	if c.Encrypter == nil {
		// 随机生成 IV，然后发送给客户端
		if _, err := io.ReadFull(rand.Reader, c.remoteBuf[:aes.IvLen]); err != nil {
			return err
		}
		c.Encrypter = aes.NewCtrEncrypter(crypto.Kdf(conf.S.Password, aes.IvLen), c.remoteBuf[:aes.IvLen])
		offset = aes.IvLen
	}
	n, err := c.remoteConn.Read(c.remoteBuf[offset:])
	if err != nil {
		return err
	}
	c.remoteBufLen = n
	c.Encrypter.Encrypt(c.remoteBuf[offset:], c.remoteBuf[offset:offset+n])
	c.remoteBufLen += offset
	return nil
}

func (c *ctx) writeClient() error {
	if c.remoteBufLen > 0 {
		n, err := c.clientConn.Write(c.remoteBuf[:c.remoteBufLen])
		if err != nil {
			return err
		}
		c.remoteBufLen -= n
	}
	return nil
}

func (c *ctx) handleStageInit() error {
	if err := c.readClient(); err != nil {
		return err
	}
	addr, offset, err := transport.ParseHeader(c.clientBuf)
	if err != nil {
		return err
	}
	c.Addr = addr
	// src 和 dst 可以重叠
	copy(c.clientBuf, c.clientBuf[offset:c.clientBufLen])
	c.clientBufLen -= offset

	c.Stage = transport.StageHandShake
	return nil
}

func (c *ctx) handleStageHandShake() error {
	golog.Info("Connecting " + c.Addr)
	conn, err := net.Dial("tcp", c.Addr)
	if err != nil {
		return err
	}
	c.remoteConn = conn.(*net.TCPConn)
	c.Stage = transport.StageStream
	return nil
}

func (c *ctx) handleStream() error {
	done := make(chan bool, 1)
	go func(c *ctx, done chan bool) {
		for {
			if err := c.readRemote(); err != nil {
				break
			}
			if err := c.writeClient(); err != nil {
				break
			}
		}
		_ = c.clientConn.Close()
		_ = c.remoteConn.Close()
		done <- true
	}(c, done)

	for {
		if err := c.writeRemote(); err != nil {
			break
		}
		if err := c.readClient(); err != nil {
			break
		}
	}
	_ = c.clientConn.Close()
	_ = c.remoteConn.Close()
	<-done
	c.Stage = transport.StageDestroyed
	// 忽略 stream 阶段出现的错误，不是很重要
	return nil
}
