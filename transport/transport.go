package transport

import (
	"errors"
	"fmt"
	"github.com/kataras/golog"
	"io"
	"net"
	"noone/conf"
	"noone/crypto"
	"time"
)

const (
	ClientBufCapacity = 4 * 1024
	RemoteBufCapacity = 4 * 1024
)

const (
	StageInit      = iota // 获取 iv 阶段
	StageHeader           // 解析 header 阶段，获取 remote 的 ip 和 port
	StageDns              // 查询 DNS，可能不进行这一步
	StageHandShake        // TCP 和 remote 握手阶段
	StageStream           // 传输阶段
	StageDestroyed        // 该连接所有资源已销毁，就剩释放 ctx 对象内存
)

// atyp
const (
	AtypIpv4   = 0x01
	AtypDomain = 0x03
	AtypIpv6   = 0x04
)

type ctx struct {
	Stage        int
	RemoteDomain string
	RemoteIp     net.IP
	RemotePort   int
	ClientConn   net.Conn
	RemoteConn   net.Conn
	Cipher       crypto.Cipher
	Iv           []byte
	ClientBuf    []byte
	ClientBufLen int
	RemoteBuf    []byte
	RemoteBufLen int
}

func New(conn net.Conn) *ctx {
	return &ctx{
		Stage:      StageInit,
		ClientConn: conn,
		ClientBuf:  make([]byte, ClientBufCapacity),
		RemoteBuf:  make([]byte, RemoteBufCapacity),
	}
}

func (c *ctx) IsDestroyed() bool {
	return c.Stage == StageDestroyed
}

func (c *ctx) ReadClient() error {
	err := c.ClientConn.SetReadDeadline(time.Now().Add(time.Minute * 2))
	if err != nil {
		return err
	}
	temp := make([]byte, ClientBufCapacity)
	n, err := c.ClientConn.Read(temp)
	if err != nil {
		return err
	}
	c.ClientBufLen = n
	c.Cipher.Decrypt(c.ClientBuf, temp[:n])
	return nil
}

func (c *ctx) WriteRemote() error {
	if c.ClientBufLen > 0 {
		err := c.RemoteConn.SetWriteDeadline(time.Now().Add(time.Minute * 2))
		if err != nil {
			return err
		}
		n, err := c.RemoteConn.Write(c.ClientBuf[:c.ClientBufLen])
		if err != nil {
			return err
		}
		c.ClientBufLen -= n
	}
	return nil
}

func (c *ctx) ReadRemote() error {
	err := c.RemoteConn.SetReadDeadline(time.Now().Add(time.Minute * 2))
	if err != nil {
		return err
	}
	n, err := c.RemoteConn.Read(c.RemoteBuf)
	if err != nil {
		return err
	}
	c.RemoteBufLen = n
	return nil
}

func (c *ctx) WriteClient() error {
	if c.RemoteBufLen > 0 {
		err := c.ClientConn.SetWriteDeadline(time.Now().Add(time.Minute * 2))
		if err != nil {
			return err
		}
		temp := make([]byte, RemoteBufCapacity)
		c.Cipher.Encrypt(temp, c.RemoteBuf[:c.RemoteBufLen])
		n, err := c.ClientConn.Write(temp[:c.RemoteBufLen])
		if err != nil {
			return err
		}
		c.RemoteBufLen -= n
	}
	return nil
}

func (c *ctx) SendIv(iv []byte) error {
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

func (c *ctx) HandleStageInit() error {
	iv := make([]byte, 16)
	_, err := io.ReadFull(c.ClientConn, iv)
	if err != nil {
		return err
	}
	c.Cipher = crypto.New(crypto.Kdf(conf.S.Password, 16), iv)
	err = c.ReadClient()
	if err != nil {
		return err
	}
	c.Iv = iv
	c.Stage = StageHeader
	return nil
}

func (c *ctx) HandleStageHeader() error {
	temp := make([]byte, c.ClientBufLen)
	copy(temp, c.ClientBuf)
	offset := 0
	atyp := temp[offset]
	offset += 1
	switch atyp {
	case AtypDomain:
		domainLen := int(temp[offset])
		offset += 1
		domain := make([]byte, domainLen)
		copy(domain, temp[offset:])
		offset += domainLen
		c.RemoteDomain = string(domain)
		c.Stage = StageDns
	case AtypIpv4:
		c.RemoteIp = make(net.IP, net.IPv4len)
		copy(c.RemoteIp, temp[offset:])
		offset += net.IPv4len
		c.Stage = StageHandShake
	case AtypIpv6:
		c.RemoteIp = make(net.IP, net.IPv6len)
		copy(c.RemoteIp, temp[offset:])
		offset += net.IPv6len
		c.Stage = StageHandShake
	default:
		return errors.New("error atyp")
	}
	c.RemotePort = (int(temp[offset]) << 8) | int(temp[offset+1])
	offset += 2
	copy(c.ClientBuf, temp[offset:])
	c.ClientBufLen -= offset
	return nil
}

func (c *ctx) HandleStageDns() error {
	// 不会使用缓存
	ipList, err := net.LookupIP(c.RemoteDomain)
	if err != nil {
		return err
	}
	c.RemoteIp = ipList[0]
	c.Stage = StageHandShake
	return nil
}

func (c *ctx) HandleStageHandShake() error {
	addr := fmt.Sprintf("%s:%d", c.RemoteIp, c.RemotePort)
	if c.RemoteDomain != "" {
		golog.Infof("connecting: %s:%d", c.RemoteDomain, c.RemotePort)
	} else {
		golog.Infof("connecting: %s", addr)
	}
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}

	c.RemoteConn = conn
	c.Stage = StageStream
	return nil
}

func (c *ctx) HandleStream() error {
	go func(c *ctx) {
		//iv := make([]byte, 16)
		//if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		//	return
		//}
		if err := c.SendIv(c.Iv); err != nil {
			return
		}
		for {
			if err := c.ReadRemote(); err != nil {
				return
			}
			if err := c.WriteClient(); err != nil {
				return
			}
		}
	}(c)

	for {
		if err := c.WriteRemote(); err != nil {
			return err
		}
		if err := c.ReadClient(); err != nil {
			return err
		}
	}
}
