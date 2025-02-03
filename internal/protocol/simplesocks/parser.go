package simplesocks

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"

	"github.com/zzzzer91/noone/internal/manager"
)

//nolint:nakedret
func ParseHeader(cmd CmdType, buf []byte) (domain string, addr net.Addr, offset int, err error) {
	if len(buf) < 7 {
		err = errors.New("header's length is invalid")
		return
	}
	var ip net.IP
	atyp := buf[offset]
	offset++
	switch atyp {
	case atypDomain:
		domainLen := int(buf[offset])
		if domainLen < 4 || len(buf[offset:]) < domainLen+2 {
			err = errors.New("domain is invalid")
			return
		}
		offset++
		domain = string(buf[offset : domainLen+offset])
		offset += domainLen
		var ips []net.IP
		ips, err = manager.M.DnsCache.LookupIP(domain)
		if err != nil {
			manager.M.DnsCache.Del(domain)
			return
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

	if domain != "" {
		domain = domain + ":" + strconv.Itoa(port)
	}

	switch cmd {
	case CmdTypeTCP:
		addr = &net.TCPAddr{
			IP:   ip,
			Port: port,
		}
	case CmdTypeUDP:
		addr = &net.UDPAddr{
			IP:   ip,
			Port: port,
		}
	default:
		err = errors.New("cmd is invalid")
		return
	}

	return
}

func BuildUDPHeader(addr string, data []byte) int {
	host, port, _ := net.SplitHostPort(addr)
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			data = data[:1+net.IPv4len]
			data[0] = atypIpv4
			copy(data[1:], ip4)
		} else {
			data = data[:1+net.IPv6len]
			data[0] = atypIpv6
			copy(data[1:], ip)
		}
	} else {
		if len(host) > 255 {
			return 0
		}
		data = data[:1+1+len(host)]
		data[0] = atypDomain
		data[1] = byte(len(host))
		copy(data[2:], host)
	}

	portnum, _ := strconv.ParseUint(port, 10, 16)
	data = binary.BigEndian.AppendUint16(data, uint16(portnum))
	data = append(data, 0, 0)
	data = append(data, Crlf...)

	return len(data)
}
