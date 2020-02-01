package transport

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/kataras/golog"
	"io"
	"net"
	"noone/conf"
	"noone/crypto"
	"noone/crypto/aes"
	"time"
)

const (
	ClientBufCapacity = 4 * 1024
	RemoteBufCapacity = 4 * 1024
	StreamTimeout     = 2 * time.Minute
)

const (
	StageInit      = iota // 获取 iv 阶段
	StageHeader           // 解析 header 阶段，获取 remote 的 ip 和 port
	StageHandShake        // TCP 和 remote 握手阶段
	StageStream           // 传输阶段
	StageDestroyed        // 该连接所有资源已销毁，就剩释放 Ctx 对象内存
)

// atyp
const (
	AtypIpv4   = 0x01
	AtypDomain = 0x03
	AtypIpv6   = 0x04
)

type Ctx struct {
	Stage        int
	RemoteHost   []byte
	RemotePort   int
	ClientConn   net.Conn
	RemoteConn   net.Conn
	cipher       crypto.Cipher
	clientBuf    []byte
	clientBufLen int
	remoteBuf    []byte
	remoteBufLen int
}

func New() *Ctx {
	return &Ctx{
		Stage:     StageInit,
		clientBuf: make([]byte, ClientBufCapacity),
		remoteBuf: make([]byte, RemoteBufCapacity),
	}
}

func (c *Ctx) Reset() {
	c.Stage = StageInit
	c.RemoteHost = nil
	c.RemotePort = 0
	if c.ClientConn != nil {
		_ = c.ClientConn.Close()
		c.ClientConn = nil
	}
	if c.RemoteConn != nil {
		_ = c.RemoteConn.Close()
		c.RemoteConn = nil
	}
	c.cipher = nil
	c.clientBufLen = 0
	c.remoteBufLen = 0
}

func (c *Ctx) readClient() error {
	err := c.ClientConn.SetReadDeadline(time.Now().Add(StreamTimeout))
	if err != nil {
		return err
	}
	n, err := c.ClientConn.Read(c.clientBuf)
	if err != nil {
		return err
	}
	c.clientBufLen = n
	c.cipher.Decrypt(c.clientBuf, c.clientBuf[:n])
	return nil
}

func (c *Ctx) writeRemote() error {
	if c.clientBufLen > 0 {
		err := c.RemoteConn.SetWriteDeadline(time.Now().Add(StreamTimeout))
		if err != nil {
			return err
		}
		n, err := c.RemoteConn.Write(c.clientBuf[:c.clientBufLen])
		if err != nil {
			return err
		}
		c.clientBufLen -= n
	}
	return nil
}

func (c *Ctx) readRemote() error {
	err := c.RemoteConn.SetReadDeadline(time.Now().Add(StreamTimeout))
	if err != nil {
		return err
	}
	n, err := c.RemoteConn.Read(c.remoteBuf)
	if err != nil {
		return err
	}
	c.cipher.Encrypt(c.remoteBuf, c.remoteBuf[:n])
	c.remoteBufLen = n
	return nil
}

func (c *Ctx) writeClient() error {
	if c.remoteBufLen > 0 {
		err := c.ClientConn.SetWriteDeadline(time.Now().Add(StreamTimeout))
		if err != nil {
			return err
		}
		n, err := c.ClientConn.Write(c.remoteBuf[:c.remoteBufLen])
		if err != nil {
			return err
		}
		c.remoteBufLen -= n
	}
	return nil
}

func (c *Ctx) sendIv(iv []byte) error {
	err := c.ClientConn.SetWriteDeadline(time.Now().Add(time.Minute * 2))
	if err != nil {
		return err
	}
	_, err = c.ClientConn.Write(iv)
	if err != nil {
		return err
	}
	return nil
}

func (c *Ctx) HandleStageInit() error {
	decryptIV := make([]byte, 16)
	if _, err := io.ReadFull(c.ClientConn, decryptIV); err != nil {
		return err
	}

	// 随机生成 IV，然后发送给客户端
	encryptIV := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, encryptIV); err != nil {
		return err
	}
	if err := c.sendIv(encryptIV); err != nil {
		return err
	}

	c.cipher = aes.NewCtr(crypto.Kdf(conf.S.Password, 16), encryptIV, decryptIV)

	if err := c.readClient(); err != nil {
		return err
	}
	c.Stage = StageHeader
	return nil
}

func (c *Ctx) HandleStageParseHeader() error {
	temp := c.clientBuf
	offset := 0
	atyp := temp[offset]
	offset += 1
	hostLen := 0
	switch atyp {
	case AtypDomain:
		hostLen = int(temp[offset])
		offset += 1
	case AtypIpv4:
		hostLen = net.IPv4len
	case AtypIpv6:
		hostLen = net.IPv6len
	default:
		return errors.New("error atyp")
	}
	c.RemoteHost = make([]byte, hostLen)
	copy(c.RemoteHost, temp[offset:])
	offset += hostLen
	c.RemotePort = (int(temp[offset]) << 8) | int(temp[offset+1])
	offset += 2
	// dst 和 src 可以重叠
	copy(c.clientBuf, temp[offset:])
	c.clientBufLen -= offset
	c.Stage = StageHandShake
	return nil
}

func (c *Ctx) HandleStageHandShake() error {
	addr := fmt.Sprintf("%s:%d", c.RemoteHost, c.RemotePort)
	golog.Infof("Connecting %s", addr)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	c.RemoteConn = conn
	c.Stage = StageStream
	return nil
}

func (c *Ctx) HandleStream() error {
	errChan := make(chan error, 1)

	go func(c *Ctx, errChan chan error) {
		for {
			if err := c.readRemote(); err != nil {
				errChan <- err
				return
			}
			if err := c.writeClient(); err != nil {
				errChan <- err
				return
			}
		}
	}(c, errChan)

	for {
		select {
		case err := <-errChan:
			return err
		default:
			if err := c.writeRemote(); err != nil {
				return err
			}
			if err := c.readClient(); err != nil {
				return err
			}
		}
	}
}
