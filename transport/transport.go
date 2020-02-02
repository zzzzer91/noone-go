package transport

import (
	"errors"
	"net"
	"strconv"
)

func ParseHeader(buf []byte) (string, int, error) {
	// 7 是头部可能最小长度（AtypIpv4 时）
	if len(buf) < 7 {
		return "", 0, errors.New("header长度不合法")
	}
	offset := 0
	atyp := buf[offset]
	offset += 1
	hostLen := 0
	switch atyp {
	case AtypDomain:
		hostLen = int(buf[offset])
		// 域名长度允许范围
		if hostLen < 4 || hostLen > 2000 {
			return "", 0, errors.New("域名长度不合法")
		}
		offset += 1
	case AtypIpv4:
		hostLen = net.IPv4len
	case AtypIpv6:
		hostLen = net.IPv6len
	default:
		return "", 0, errors.New("atyp不合法")
	}
	// hostLen 长度要检查，不然会被爆内存
	host := make([]byte, hostLen)
	copy(host, buf[offset:])
	offset += hostLen
	port := (int(buf[offset]) << 8) | int(buf[offset+1])
	offset += 2
	if atyp == AtypIpv4 || atyp == AtypIpv6 {
		return net.IP(host).String() + ":" + strconv.Itoa(port), offset, nil
	}
	return string(host) + ":" + strconv.Itoa(port), offset, nil
}
