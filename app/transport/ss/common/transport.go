package common

import (
	"errors"
	"net"
	"noone/app/crypto"
	"noone/app/manager"
	"noone/app/user"
)

// atyp
const (
	AtypIpv4   = 0x01
	AtypDomain = 0x03
	AtypIpv6   = 0x04
)

type Ctx struct {
	Network      string
	RemoteDomain string
	RemotePort   int
	Info         string
	ClientAddr   net.Addr
	RemoteAddr   net.Addr
	Encrypter    crypto.Encrypter
	Decrypter    crypto.Decrypter
	UserInfo     *user.User
}

func (c *Ctx) Reset() {
	// some fields don't need reset, e.g., Network
	c.RemoteDomain = ""
	c.RemotePort = 0
	c.ClientAddr = nil
	c.RemoteAddr = nil
	c.Encrypter = nil
	c.Decrypter = nil
	c.UserInfo = nil
}

func (c *Ctx) ParseHeader(buf []byte) (offset int, err error) {
	if len(buf) < 7 {
		return 0, errors.New("header's length is invalid")
	}
	var ip net.IP
	atyp := buf[offset]
	offset += 1
	switch atyp {
	case AtypDomain:
		domainLen := int(buf[offset])
		if domainLen < 4 || len(buf[offset:]) < domainLen+2 {
			return 0, errors.New("domain is invalid")
		}
		offset += 1
		c.RemoteDomain = string(buf[offset : domainLen+offset])
		offset += domainLen
		ips, err := manager.M.DnsCache.LookupIP(c.RemoteDomain)
		if err != nil {
			manager.M.DnsCache.Del(c.RemoteDomain)
			return 0, err
		}
		// select first IP
		ip = ips[0]
	case AtypIpv4:
		if len(buf[offset:]) < net.IPv4len+2 {
			return 0, errors.New("Ipv4 is invalid")
		}
		ip = make(net.IP, net.IPv4len)
		copy(ip, buf[offset:])
		offset += net.IPv4len
	case AtypIpv6:
		if len(buf[offset:]) < net.IPv6len+2 {
			return 0, errors.New("Ipv6 is invalid")
		}
		ip = make(net.IP, net.IPv6len)
		copy(ip, buf[offset:])
		offset += net.IPv6len
	default:
		return 0, errors.New("atyp is invalid")
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
		return 0, errors.New("network is invalid")
	}

	return offset, nil
}
