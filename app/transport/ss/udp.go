package ss

import (
	"net"
	"noone/app/crypto"
	"noone/app/crypto/aes"
	"strconv"

	"github.com/sirupsen/logrus"
)

type udpCtx struct {
	SsCtx
	lClient   *net.UDPConn
	lRemote   *net.UDPConn
	encrypter crypto.Encrypter
	decrypter crypto.Decrypter
	conf      *ssConf
}

func newUdpCtx() *udpCtx {
	return &udpCtx{
		SsCtx: SsCtx{
			Network:   "udp",
			ClientBuf: make([]byte, udpClientBufCapacity),
			RemoteBuf: make([]byte, udpRemoteBufCapacity),
		},
	}
}

func (c *udpCtx) reset() {
	c.SsCtx.Reset()
	c.lClient = nil
	c.lRemote = nil
	c.encrypter = nil
	c.decrypter = nil
	c.conf = nil
}

func runUdp(conf *ssConf) {
	udpAddr, err := net.ResolveUDPAddr("udp", conf.server+":"+strconv.Itoa(conf.port))
	if err != nil {
		logrus.Fatal(err)
	}
	lClient, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		logrus.Fatal(err)
	}
	clientBuf := make([]byte, udpClientBufCapacity)
	for {
		clientReadN, clientAddr, err := lClient.ReadFrom(clientBuf)
		logrus.Info("UDP readfrom " + clientAddr.String())
		if err != nil {
			logrus.Error(err)
			continue
		}
		if clientReadN < aes.IvLen+7 {
			logrus.Error("header's length is invalid")
			continue
		}

		c := udpCtxPool.Get().(*udpCtx)
		c.ClientAddr = clientAddr
		c.decrypter = aes.NewCtrDecrypter(conf.Key, clientBuf[:aes.IvLen])
		c.lClient = lClient
		c.decrypter.Decrypt(c.ClientBuf, clientBuf[aes.IvLen:clientReadN])
		c.ClientBufLen = clientReadN - aes.IvLen

		go handleUdp(c)
	}
}

func handleUdp(c *udpCtx) {
	defer udpCtxPool.Put(c)
	defer c.reset()

	offset, err := c.ParseHeader(c.ClientBuf[:c.ClientBufLen])
	if err != nil {
		logrus.Error(err)
		return
	}
	c.ClientBufIdx += offset
	if c.ClientBufIdx == c.ClientBufLen {
		logrus.Error("udp no more data")
		return
	}

	// 绑定随机地址
	c.lRemote, err = net.ListenUDP("udp", nil)
	defer c.lRemote.Close()
	if err != nil {
		logrus.Error(err)
		return
	}
	logrus.Info("UDP sendto " + c.RemoteAddr.String())
	_, err = c.lRemote.WriteTo(c.ClientBuf[c.ClientBufIdx:c.ClientBufLen], c.RemoteAddr)
	if err != nil {
		logrus.Error(err)
		return
	}
	if err := aes.GenRandomIv(c.RemoteBuf[:aes.IvLen]); err != nil {
		logrus.Error(err)
		return
	}
	c.encrypter = aes.NewCtrEncrypter(c.conf.Key, c.RemoteBuf[:aes.IvLen])
	offset = buildSendClientHeader(c.RemoteBuf[aes.IvLen:], c.RemoteAddr.(*net.UDPAddr))
	n, addr, err := c.lRemote.ReadFrom(c.RemoteBuf[aes.IvLen+offset:])
	if err != nil {
		logrus.Error(err)
		return
	}
	if addr.String() != c.RemoteAddr.String() {
		logrus.Error("the sent address is not equal to the received address")
		return
	}
	n += aes.IvLen + offset
	c.encrypter.Encrypt(c.RemoteBuf[aes.IvLen:n], c.RemoteBuf[aes.IvLen:n])
	_, err = c.lClient.WriteTo(c.RemoteBuf[:n], c.ClientAddr)
	if err != nil {
		logrus.Error(err)
		return
	}
}

func buildSendClientHeader(buf []byte, remoteAddr *net.UDPAddr) int {
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
