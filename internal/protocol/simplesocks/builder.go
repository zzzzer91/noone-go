package simplesocks

import "net"

func BuildUdpHeader(buf []byte, remoteAddr *net.UDPAddr) int {
	offset := 0
	if ipv4 := remoteAddr.IP.To4(); ipv4 != nil {
		buf[offset] = atypIpv4
		offset += 1
		copy(buf[offset:], ipv4)
		offset += net.IPv4len
	} else {
		buf[offset] = atypIpv6
		offset += 1
		copy(buf[offset:], remoteAddr.IP)
		offset += net.IPv6len
	}
	buf[offset], buf[offset+1] = byte(remoteAddr.Port>>8), byte(remoteAddr.Port)
	offset += 2
	return offset
}
