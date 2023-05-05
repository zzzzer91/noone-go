package ss

import (
	"net"
	"noone/app/crypto"
	"noone/app/crypto/aes"
	"noone/app/protocol/simplesocks"
	"noone/app/transport/pure"

	"github.com/zzzzer91/gopkg/logx"
)

func runUdp(conf *ssConf) {
	udpAddr, err := net.ResolveUDPAddr("udp", conf.addr)
	if err != nil {
		logx.Fatal(err)
	}
	lClient, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		logx.Fatal(err)
	}
	clientBuf := make([]byte, pure.UdpClientBufCapacity)
	for {
		clientReadN, clientAddr, err := lClient.ReadFrom(clientBuf)
		logx.Info("UDP readfrom " + clientAddr.String())
		if err != nil {
			logx.Error(err)
			continue
		}
		if clientReadN < aes.IvLen+7 {
			logx.Error("header's length is invalid")
			continue
		}

		c := udpCtxPool.Get().(*ssUdpCtx)
		c.ClientAddr = clientAddr
		c.decrypter = aes.NewCtrDecrypter(conf.Key, clientBuf[:aes.IvLen])
		c.lClient = lClient
		c.decrypter.Decrypt(c.ClientBuf, clientBuf[aes.IvLen:clientReadN])
		c.ClientBufLen = clientReadN - aes.IvLen

		go handleUdp(c)
	}
}

func handleUdp(c *ssUdpCtx) {
	defer udpCtxPool.Put(c)
	defer c.reset()

	domain, remoteAddr, offset, err := simplesocks.ParseHeader(c.Network, c.ClientBuf[:c.ClientBufLen])
	if err != nil {
		logx.Error(err)
		return
	}
	c.ClientBufIdx += offset
	if c.ClientBufIdx == c.ClientBufLen {
		logx.Error("udp no more data")
		return
	}
	c.RemoteDomain = domain
	c.RemoteAddr = remoteAddr

	// 绑定随机地址
	c.lRemote, err = net.ListenUDP("udp", nil)
	defer c.lRemote.Close()
	if err != nil {
		logx.Error(err)
		return
	}
	logx.Info("UDP sendto " + c.RemoteAddr.String())
	_, err = c.lRemote.WriteTo(c.ClientBuf[c.ClientBufIdx:c.ClientBufLen], c.RemoteAddr)
	if err != nil {
		logx.Error(err)
		return
	}
	if err := aes.GenRandomIv(c.RemoteBuf[:aes.IvLen]); err != nil {
		logx.Error(err)
		return
	}
	c.encrypter = aes.NewCtrEncrypter(c.conf.Key, c.RemoteBuf[:aes.IvLen])
	offset = simplesocks.BuildUdpHeader(c.RemoteBuf[aes.IvLen:], c.RemoteAddr.(*net.UDPAddr))
	n, addr, err := c.lRemote.ReadFrom(c.RemoteBuf[aes.IvLen+offset:])
	if err != nil {
		logx.Error(err)
		return
	}
	if addr.String() != c.RemoteAddr.String() {
		logx.Error("the sent address is not equal to the received address")
		return
	}
	n += aes.IvLen + offset
	c.encrypter.Encrypt(c.RemoteBuf[aes.IvLen:n], c.RemoteBuf[aes.IvLen:n])
	_, err = c.lClient.WriteTo(c.RemoteBuf[:n], c.ClientAddr)
	if err != nil {
		logx.Error(err)
		return
	}
}

type ssUdpCtx struct {
	*pure.UdpCtx
	lClient   *net.UDPConn
	lRemote   *net.UDPConn
	encrypter crypto.Encrypter
	decrypter crypto.Decrypter
	conf      *ssConf
}

func newSsUdpCtx() *ssUdpCtx {
	return &ssUdpCtx{
		UdpCtx: pure.NewUdpCtx(),
	}
}

func (c *ssUdpCtx) reset() {
	c.UdpCtx.Reset()
	c.lClient = nil
	c.lRemote = nil
	c.encrypter = nil
	c.decrypter = nil
	c.conf = nil
}
