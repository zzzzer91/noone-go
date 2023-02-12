package tcp

import (
	"errors"
	"fmt"
	"net"
	"noone/app/crypto/aes"
	"noone/app/transport"

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
	c.clientBufLen = n
	c.clientBufIdx = 0
	if c.Decrypter == nil {
		if n < aes.IvLen {
			return errors.New("IV length is invaild")
		}
		c.Decrypter = aes.NewCtrDecrypter(c.UserInfo.Key, c.clientBuf[:aes.IvLen])
		c.clientBufLen -= aes.IvLen
		c.clientBufIdx += aes.IvLen
		if c.clientBufLen == 0 {
			return nil
		}
	}
	// Decrypt 和 Encrypt 的 dst 和 src 内存区域允许重叠，但是有条件：
	// 那就是 &dst[0] 和 &src[0] 必须相同
	tmp := c.clientBuf[c.clientBufIdx : c.clientBufIdx+c.clientBufLen]
	c.Decrypter.Decrypt(tmp, tmp)
	return nil
}

func (c *ctx) writeRemote() error {
	for c.clientBufLen > 0 {
		n, err := c.remoteConn.Write(c.clientBuf[c.clientBufIdx : c.clientBufIdx+c.clientBufLen])
		if err != nil {
			return err
		}
		c.clientBufLen -= n
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
	c.remoteBufLen = n + offset
	c.remoteBufIdx = 0
	c.Encrypter.Encrypt(c.remoteBuf[offset:c.remoteBufLen], c.remoteBuf[offset:c.remoteBufLen])
	return nil
}

func (c *ctx) writeClient() error {
	// logrus.Debug("writeClient: " + strconv.Itoa(c.remoteBufLen))

	// 发送缓冲区可能满，这个时候要不停写，直到写完
	for c.remoteBufLen > 0 {
		n, err := c.clientConn.Write(c.remoteBuf[c.remoteBufIdx : c.remoteBufIdx+c.remoteBufLen])
		if err != nil {
			return err
		}
		c.remoteBufLen -= n
		c.remoteBufIdx += n
	}
	return nil
}

func (c *ctx) handleStageInit() error {
	if err := c.readClient(); err != nil {
		return err
	}
	if c.clientBufLen == 0 { // 可能第一次只发Decrypter过来
		return nil
	}
	offset, err := c.ParseHeader(c.clientBuf[c.clientBufIdx : c.clientBufIdx+c.clientBufLen])
	if err != nil {
		return err
	}
	c.clientBufLen -= offset
	c.clientBufIdx += offset

	c.Stage = transport.StageHandShake
	return nil
}

func (c *ctx) handleStageHandShake() error {
	var target string
	if c.RemoteDomain != "" { // 优先打印域名
		target = fmt.Sprintf("%s (%s)", c.RemoteDomain, c.RemoteAddr.String())
	} else {
		target = c.RemoteAddr.String()
	}
	logrus.Info("Connecting " + target)
	conn, err := net.DialTCP("tcp", nil, c.RemoteAddr.(*net.TCPAddr))
	if err != nil {
		return errors.New("Connect " + target + " error: " + err.Error())
	}
	c.remoteConn = conn
	err = c.remoteConn.SetKeepAlive(true)
	if err != nil {
		return err
	}
	logrus.Info("Connected " + target)
	c.Stage = transport.StageStream
	return nil
}

func (c *ctx) handleStageStream() error {
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
