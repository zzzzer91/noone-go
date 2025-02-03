package simplesocks

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"

	"github.com/zzzzer91/gopkg/pool"
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

func BuildUDPPacket(addr net.Addr, data []byte) []byte {
	packet := pool.Get(len(data) + MaxUDPHeaderLength)
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			packet = packet[:1+net.IPv4len]
			packet[0] = atypIpv4
			copy(packet[1:], ip4)
		} else {
			packet = packet[:1+net.IPv6len]
			packet[0] = atypIpv6
			copy(packet[1:], ip)
		}
	} else {
		if len(host) > 255 {
			return nil
		}
		packet = packet[:1+1+len(host)]
		packet[0] = atypDomain
		packet[1] = byte(len(host))
		copy(packet[2:], host)
	}

	portnum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil
	}
	packet = binary.BigEndian.AppendUint16(packet, uint16(portnum))
	packet = binary.BigEndian.AppendUint16(packet, uint16(len(data)))
	packet = append(packet, Crlf...)
	packet = append(packet, data...)

	return packet
}
