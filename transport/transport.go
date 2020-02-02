package transport

import (
	"errors"
	"net"
	"strconv"
)

const (
	ClientBufCapacity = 8 * 1024
	RemoteBufCapacity = 8 * 1024
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
		offset += 1
	case AtypIpv4:
		hostLen = net.IPv4len
	case AtypIpv6:
		hostLen = net.IPv6len
	default:
		return "", 0, errors.New("atyp不合法")
	}
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
