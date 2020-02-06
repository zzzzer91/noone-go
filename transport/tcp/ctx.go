package tcp

import (
	"errors"
	"github.com/kataras/golog"
	"net"
	"noone/crypto/aes"
	"noone/transport"
	"strconv"
)

type ctx struct {
	transport.Ctx
	clientConn   *net.TCPConn
	remoteConn   *net.TCPConn
	clientBuf    []byte
	clientBufLen int
	remoteBuf    []byte
	remoteBufLen int
}

func (c *ctx) reset() {
	c.Ctx.Reset()
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
		c.Decrypter = aes.NewCtrDecrypter(c.UserInfo.Key, c.clientBuf[:aes.IvLen])
		c.clientBufLen -= aes.IvLen
		if c.clientBufLen == 0 {
			return nil
		}
		copy(c.clientBuf, c.clientBuf[aes.IvLen:n])
	}
	// Decrypt 和 Encrypt 的 dst 和 src 内存区域允许重叠，但是有条件：
	// 那就是 &dst[0] 和 &src[0] 必须相同
	c.Decrypter.Decrypt(c.clientBuf[:c.clientBufLen], c.clientBuf[:c.clientBufLen])
	return nil
}

func (c *ctx) writeRemote() error {
	offset := 0
	for c.clientBufLen > 0 {
		n, err := c.remoteConn.Write(c.clientBuf[offset : c.clientBufLen+offset])
		if err != nil {
			return err
		}
		offset += n
		c.clientBufLen -= n
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
	c.remoteBufLen = n + offset
	c.Encrypter.Encrypt(c.remoteBuf[offset:c.remoteBufLen], c.remoteBuf[offset:c.remoteBufLen])
	return nil
}

func (c *ctx) writeClient() error {
	// golog.Debug("writeClient: " + strconv.Itoa(c.remoteBufLen))

	// 发送缓冲区可能满，这个时候要不停写，直到写完
	offset := 0
	for c.remoteBufLen > 0 {
		n, err := c.clientConn.Write(c.remoteBuf[offset : c.remoteBufLen+offset])
		if err != nil {
			return err
		}
		offset += n
		c.remoteBufLen -= n
	}
	return nil
}

func (c *ctx) handleStageInit() error {
	if err := c.readClient(); err != nil {
		return err
	}
	offset, err := c.ParseHeader(c.clientBuf[:c.clientBufLen])
	if err != nil {
		return err
	}
	// src 和 dst 可以重叠
	copy(c.clientBuf, c.clientBuf[offset:c.clientBufLen])
	c.clientBufLen -= offset

	c.Stage = transport.StageHandShake
	return nil
}

func (c *ctx) handleStageHandShake() error {
	var temp string
	if c.RemoteDomain != "" { // 优先打印域名
		temp = c.RemoteDomain + ":" + strconv.Itoa(c.RemotePort)
	} else {
		temp = c.RemoteAddr.String()
	}
	golog.Info("Connecting " + temp)
	conn, err := net.DialTCP("tcp", nil, c.RemoteAddr.(*net.TCPAddr))
	if err != nil {
		// 这个 Domain 对应的 IP 已经过期，把它从缓存删除
		// TODO，当访问被墙域名时，会不停的加入缓存和从缓存删除
		//if c.RemoteDomain != "" {
		//	c.UserInfo.DnsCache.Del(c.RemoteDomain)
		//}
		return errors.New("Connect " + temp + " error: " + err.Error())
	}
	c.remoteConn = conn
	err = c.remoteConn.SetKeepAlive(true)
	if err != nil {
		return err
	}
	golog.Info("Connected " + temp)
	c.Stage = transport.StageStream
	return nil
}

func (c *ctx) handleStream() error {
	done := make(chan bool, 1)
	defer close(done)
	go func(c *ctx) {
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
	}(c)

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
	// 暂时忽略 stream 阶段出现的错误
	return nil
}
