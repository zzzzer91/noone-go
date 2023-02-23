package simplesocks

import (
	"errors"
	"net"
	"noone/app/manager"
)

type Data struct {
	Domain string
	Addr   net.Addr
}

func ParseHeader(network string, buf []byte) (domain string, addr net.Addr, offset int, err error) {
	if len(buf) < 7 {
		err = errors.New("header's length is invalid")
		return
	}
	var ip net.IP
	atyp := buf[offset]
	offset += 1
	switch atyp {
	case atypDomain:
		domainLen := int(buf[offset])
		if domainLen < 4 || len(buf[offset:]) < domainLen+2 {
			err = errors.New("domain is invalid")
			return
		}
		offset += 1
		domain = string(buf[offset : domainLen+offset])
		offset += domainLen
		ips, err := manager.M.DnsCache.LookupIP(domain)
		if err != nil {
			manager.M.DnsCache.Del(domain)
			return "", nil, 0, err
		}
		// select first IP
		ip = ips[0]
	case atypIpv4:
		if len(buf[offset:]) < net.IPv4len+2 {
			err = errors.New("Ipv4 is invalid")
			return
		}
		ip = make(net.IP, net.IPv4len)
		copy(ip, buf[offset:])
		offset += net.IPv4len
	case atypIpv6:
		if len(buf[offset:]) < net.IPv6len+2 {
			err = errors.New("Ipv6 is invalid")
			return
		}
		ip = make(net.IP, net.IPv6len)
		copy(ip, buf[offset:])
		offset += net.IPv6len
	default:
		err = errors.New("atyp is invalid")
		return
	}
	port := (int(buf[offset]) << 8) | int(buf[offset+1])
	offset += 2

	switch network {
	case "tcp":
		addr = &net.TCPAddr{
			IP:   ip,
			Port: port,
		}
	case "udp":
		addr = &net.UDPAddr{
			IP:   ip,
			Port: port,
		}
	default:
		err = errors.New("network is invalid")
		return
	}

	return
}
