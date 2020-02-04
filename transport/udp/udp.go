package udp

import (
	"github.com/kataras/golog"
	"net"
	"noone/conf"
	"noone/crypto"
	"noone/crypto/aes"
	"noone/transport"
)

func Run(addr string) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		golog.Fatal(err)
	}
	lClient, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		golog.Fatal(err)
	}
	clientBuf := make([]byte, clientBufCapacity)
	for {
		clientReadN, clientAddr, err := lClient.ReadFrom(clientBuf)
		if err != nil {
			golog.Error(err)
			continue
		}
		if clientReadN < aes.IvLen+7 {
			golog.Error("头部长度不合法")
			continue
		}
		c := newCtx()
		c.lClient = lClient
		c.ClientAddr = clientAddr
		golog.Info("UDP readfrom " + c.ClientAddr.String())

		c.Decrypter = aes.NewCtrDecrypter(crypto.Kdf(conf.S.Password, aes.IvLen), clientBuf[:aes.IvLen])
		copy(clientBuf, clientBuf[aes.IvLen:clientReadN])
		clientReadN -= aes.IvLen
		c.Decrypter.Decrypt(clientBuf, clientBuf[:clientReadN])
		domain, ip, port, offset, err := transport.ParseHeader(clientBuf)
		if err != nil {
			golog.Error(err)
			continue
		}
		clientReadN -= offset
		if clientReadN <= 0 {
			golog.Error("udp没有数据")
			continue
		}
		c.RemoteDomain = domain
		c.RemotePort = port
		c.RemoteAddr = &net.UDPAddr{
			IP:   ip,
			Port: port,
			Zone: "",
		}

		// 绑定随机地址
		c.lRemote, err = net.ListenUDP("udp", nil)
		if err != nil {
			golog.Error(err)
			continue
		}

		golog.Info("UDP sendto " + c.RemoteAddr.String())
		_, err = c.lRemote.WriteTo(clientBuf[offset:clientReadN+offset], c.RemoteAddr.(*net.UDPAddr))
		if err != nil {
			golog.Error(err)
			continue
		}

		go func(c *ctx) {
			remoteBuf := make([]byte, remoteBufCapacity)
			if err := aes.GenRandomIv(remoteBuf[:aes.IvLen]); err != nil {
				return
			}
			offset, err := buildSendClientHeader(remoteBuf[aes.IvLen:], c.RemoteAddr.(*net.UDPAddr))
			n, addr, err := c.lRemote.ReadFrom(remoteBuf[aes.IvLen+offset:])
			if err != nil {
				return
			}
			if addr.String() != c.RemoteAddr.String() {
				return
			}
			n += aes.IvLen + offset
			c.Encrypter = aes.NewCtrEncrypter(crypto.Kdf(conf.S.Password, aes.IvLen), remoteBuf[:aes.IvLen])
			c.Encrypter.Encrypt(remoteBuf[aes.IvLen:n], remoteBuf[aes.IvLen:n])
			_, err = c.lClient.WriteTo(remoteBuf[:n], c.ClientAddr.(*net.UDPAddr))
			if err != nil {
				return
			}
		}(c)
	}
}

func buildSendClientHeader(buf []byte, remoteAddr *net.UDPAddr) (int, error) {
	offset := 0
	if ipv4 := remoteAddr.IP.To4(); ipv4 != nil {
		buf[offset] = transport.AtypIpv4
		offset += 1
		copy(buf[offset:], ipv4)
		offset += net.IPv4len
	} else {
		buf[offset] = transport.AtypIpv6
		offset += 1
		copy(buf[offset:], remoteAddr.IP)
		offset += net.IPv6len
	}
	buf[offset], buf[offset+1] = byte(remoteAddr.Port>>8), byte(remoteAddr.Port)
	offset += 2
	return offset, nil
}
