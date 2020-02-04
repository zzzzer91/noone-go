package transport

import (
	"errors"
	"net"
)

func ParseHeader(buf []byte) (string, net.IP, int, int, error) {
	// 7 是头部可能最小长度（AtypIpv4 时）
	if len(buf) < 7 {
		return "", nil, 0, 0, errors.New("header长度不合法")
	}
	var domain string
	var ip net.IP
	offset := 0
	atyp := buf[offset]
	offset += 1
	switch atyp {
	case AtypDomain:
		domainLen := int(buf[offset])
		// 域名长度允许范围
		if domainLen < 4 || domainLen > 2000 {
			return "", nil, 0, 0, errors.New("域名长度不合法")
		}
		offset += 1
		// domainLen 长度要检查，不然会被爆内存
		domainBytes := make([]byte, domainLen)
		copy(domainBytes, buf[offset:])
		offset += domainLen
		// 解析IP
		domain = string(domainBytes)
		ips, err := net.LookupIP(domain)
		if err != nil {
			return "", nil, 0, 0, err
		}
		// 选取第一个
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
		return "", nil, 0, 0, errors.New("atyp不合法")
	}
	port := (int(buf[offset]) << 8) | int(buf[offset+1])
	offset += 2
	return domain, ip, port, offset, nil
}
