package udp

import (
	"net"
	"noone/app/crypto/aes"
	"noone/app/manager"
	"noone/app/transport/ss/common"
	"strconv"

	"github.com/sirupsen/logrus"
)

func Run(proxy *manager.Proxy) {
	udpAddr, err := net.ResolveUDPAddr("udp", proxy.Server+":"+strconv.Itoa(proxy.Port))
	if err != nil {
		logrus.Fatal(err)
	}
	lClient, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		logrus.Fatal(err)
	}
	clientBuf := make([]byte, clientBufCapacity)
	for {
		clientReadN, clientAddr, err := lClient.ReadFrom(clientBuf)
		if err != nil {
			logrus.Error(err)
			continue
		}
		if clientReadN < aes.IvLen+7 {
			logrus.Error("头部长度不合法")
			continue
		}
		c := &ctx{
			Ctx: common.Ctx{
				Network:    "udp",
				UserInfo:   proxy,
				ClientAddr: clientAddr,
				Decrypter:  aes.NewCtrDecrypter(proxy.Key, clientBuf[:aes.IvLen]),
			},
			lClient: lClient,
		}
		logrus.Info("UDP readfrom " + c.ClientAddr.String())

		copy(clientBuf, clientBuf[aes.IvLen:clientReadN])
		clientReadN -= aes.IvLen
		c.Decrypter.Decrypt(clientBuf, clientBuf[:clientReadN])
		offset, err := c.ParseHeader(clientBuf[:clientReadN])
		if err != nil {
			logrus.Error(err)
			continue
		}
		clientReadN -= offset
		if clientReadN <= 0 {
			logrus.Error("udp没有数据")
			continue
		}

		// 绑定随机地址
		c.lRemote, err = net.ListenUDP("udp", nil)
		if err != nil {
			logrus.Error(err)
			continue
		}
		logrus.Info("UDP sendto " + c.RemoteAddr.String())
		_, err = c.lRemote.WriteTo(clientBuf[offset:clientReadN+offset], c.RemoteAddr)
		if err != nil {
			logrus.Error(err)
			continue
		}

		go func(c *ctx) {
			defer c.lRemote.Close()
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
			c.Encrypter = aes.NewCtrEncrypter(c.UserInfo.Key, remoteBuf[:aes.IvLen])
			c.Encrypter.Encrypt(remoteBuf[aes.IvLen:n], remoteBuf[aes.IvLen:n])
			_, err = c.lClient.WriteTo(remoteBuf[:n], c.ClientAddr)
			if err != nil {
				return
			}
		}(c)
	}
}

func buildSendClientHeader(buf []byte, remoteAddr *net.UDPAddr) (int, error) {
	offset := 0
	if ipv4 := remoteAddr.IP.To4(); ipv4 != nil {
		buf[offset] = common.AtypIpv4
		offset += 1
		copy(buf[offset:], ipv4)
		offset += net.IPv4len
	} else {
		buf[offset] = common.AtypIpv6
		offset += 1
		copy(buf[offset:], remoteAddr.IP)
		offset += net.IPv6len
	}
	buf[offset], buf[offset+1] = byte(remoteAddr.Port>>8), byte(remoteAddr.Port)
	offset += 2
	return offset, nil
}
