package ss

import (
	"errors"
	"net"
	"noone/app/crypto"
	"noone/app/manager"
)

type ssCtx struct {
	network      string
	remoteDomain string
	remotePort   int
	info         string
	clientAddr   net.Addr
	remoteAddr   net.Addr
	encrypter    crypto.Encrypter
	decrypter    crypto.Decrypter
	conf         *ssConf
}

func (c *ssCtx) reset() {
	// some fields don't need reset, e.g., network
	c.remoteDomain = ""
	c.remotePort = 0
	c.clientAddr = nil
	c.remoteAddr = nil
	c.encrypter = nil
	c.decrypter = nil
	c.conf = nil
}

func (c *ssCtx) parseHeader(buf []byte) (offset int, err error) {
	if len(buf) < 7 {
		return 0, errors.New("header's length is invalid")
	}
	var ip net.IP
	atyp := buf[offset]
	offset += 1
	switch atyp {
	case atypDomain:
		domainLen := int(buf[offset])
		if domainLen < 4 || len(buf[offset:]) < domainLen+2 {
			return 0, errors.New("domain is invalid")
		}
		offset += 1
		c.remoteDomain = string(buf[offset : domainLen+offset])
		offset += domainLen
		ips, err := manager.M.DnsCache.LookupIP(c.remoteDomain)
		if err != nil {
			manager.M.DnsCache.Del(c.remoteDomain)
			return 0, err
		}
		// select first IP
		ip = ips[0]
	case atypIpv4:
		if len(buf[offset:]) < net.IPv4len+2 {
			return 0, errors.New("Ipv4 is invalid")
		}
		ip = make(net.IP, net.IPv4len)
		copy(ip, buf[offset:])
		offset += net.IPv4len
	case atypIpv6:
		if len(buf[offset:]) < net.IPv6len+2 {
			return 0, errors.New("Ipv6 is invalid")
		}
		ip = make(net.IP, net.IPv6len)
		copy(ip, buf[offset:])
		offset += net.IPv6len
	default:
		return 0, errors.New("atyp is invalid")
	}
	c.remotePort = (int(buf[offset]) << 8) | int(buf[offset+1])
	offset += 2

	switch c.network {
	case "tcp":
		c.remoteAddr = &net.TCPAddr{
			IP:   ip,
			Port: c.remotePort,
		}
	case "udp":
		c.remoteAddr = &net.UDPAddr{
			IP:   ip,
			Port: c.remotePort,
		}
	default:
		return 0, errors.New("network is invalid")
	}

	return offset, nil
}
