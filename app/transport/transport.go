package transport

import (
	"errors"
	"net"
	"noone/app/crypto"
	"noone/app/manager"
	"noone/app/user"
)

const (
	StageInit      = iota // 解析 header 阶段，获取 iv, remote 的 ip 和 port
	StageHandShake        // TCP 和 remote 握手阶段
	StageStream           // TCP 传输阶段
	StageDestroyed        // 该连接已销毁
)

// atyp
const (
	AtypIpv4   = 0x01
	AtypDomain = 0x03
	AtypIpv6   = 0x04
)

type Ctx struct {
	Network      string
	Stage        int
	RemoteDomain string
	RemotePort   int
	ClientAddr   net.Addr
	RemoteAddr   net.Addr
	Encrypter    crypto.Encrypter
	Decrypter    crypto.Decrypter
	UserInfo     *user.User
}

func (c *Ctx) Reset() {
	// some fields don't need reset, e.g., Network
	c.Stage = StageInit
	c.RemoteDomain = ""
	c.RemotePort = 0
	c.ClientAddr = nil
	c.RemoteAddr = nil
	c.Encrypter = nil
	c.Decrypter = nil
	c.UserInfo = nil
}

func (c *Ctx) ParseHeader(buf []byte) (offset int, err error) {
	// 头部可能最小长度（AtypIpv4 时）
	if len(buf) < 7 {
		return 0, errors.New("header长度不合法")
	}
	var ip net.IP
	atyp := buf[offset]
	offset += 1
	switch atyp {
	case AtypDomain:
		domainLen := int(buf[offset])
		// 域名长度允许范围
		if domainLen < 4 || domainLen > 2000 {
			return 0, errors.New("域名长度不合法")
		}
		offset += 1
		// 解析IP
		c.RemoteDomain = string(buf[offset : domainLen+offset])
		offset += domainLen
		ips, err := manager.M.DnsCache.LookupIP(c.RemoteDomain)
		if err != nil {
			manager.M.DnsCache.Del(c.RemoteDomain)
			return 0, err
		}
		// 暂时先选取第一个 IP
		ip = ips[0]
	case AtypIpv4:
		ip = make(net.IP, net.IPv4len)
		copy(ip, buf[offset:])
		offset += net.IPv4len
	case AtypIpv6:
		ip = make(net.IP, net.IPv6len)
		copy(ip, buf[offset:])
		offset += net.IPv6len
	default:
		return 0, errors.New("atyp不合法")
	}
	c.RemotePort = (int(buf[offset]) << 8) | int(buf[offset+1])
	offset += 2

	switch c.Network {
	case "tcp":
		c.RemoteAddr = &net.TCPAddr{
			IP:   ip,
			Port: c.RemotePort,
		}
	case "udp":
		c.RemoteAddr = &net.UDPAddr{
			IP:   ip,
			Port: c.RemotePort,
		}
	default:
		return 0, errors.New("network不合法")
	}

	return offset, nil
}
