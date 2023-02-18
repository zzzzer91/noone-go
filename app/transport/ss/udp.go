package ss

import (
	"net"
	"noone/app/crypto/aes"
	"strconv"

	"github.com/sirupsen/logrus"
)

type udpCtx struct {
	ssCtx
	lClient *net.UDPConn
	lRemote *net.UDPConn
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
		if err != nil {
			logrus.Error(err)
			continue
		}
		if clientReadN < aes.IvLen+7 {
			logrus.Error("header's length is invalid")
			continue
		}
		c := &udpCtx{
			ssCtx: ssCtx{
				network:    "udp",
				conf:       conf,
				clientAddr: clientAddr,
				decrypter:  aes.NewCtrDecrypter(conf.Key, clientBuf[:aes.IvLen]),
			},
			lClient: lClient,
		}
		logrus.Info("UDP readfrom " + c.clientAddr.String())

		copy(clientBuf, clientBuf[aes.IvLen:clientReadN])
		clientReadN -= aes.IvLen
		c.decrypter.Decrypt(clientBuf, clientBuf[:clientReadN])
		offset, err := c.parseHeader(clientBuf[:clientReadN])
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
		logrus.Info("UDP sendto " + c.remoteAddr.String())
		_, err = c.lRemote.WriteTo(clientBuf[offset:clientReadN+offset], c.remoteAddr)
		if err != nil {
			logrus.Error(err)
			continue
		}

		go func(c *udpCtx) {
			defer c.lRemote.Close()
			remoteBuf := make([]byte, udpRemoteBufCapacity)
			if err := aes.GenRandomIv(remoteBuf[:aes.IvLen]); err != nil {
				return
			}
			offset, err := buildSendClientHeader(remoteBuf[aes.IvLen:], c.remoteAddr.(*net.UDPAddr))
			n, addr, err := c.lRemote.ReadFrom(remoteBuf[aes.IvLen+offset:])
			if err != nil {
				return
			}
			if addr.String() != c.remoteAddr.String() {
				return
			}
			n += aes.IvLen + offset
			c.encrypter = aes.NewCtrEncrypter(c.conf.Key, remoteBuf[:aes.IvLen])
			c.encrypter.Encrypt(remoteBuf[aes.IvLen:n], remoteBuf[aes.IvLen:n])
			_, err = c.lClient.WriteTo(remoteBuf[:n], c.clientAddr)
			if err != nil {
				return
			}
		}(c)
	}
}

func buildSendClientHeader(buf []byte, remoteAddr *net.UDPAddr) (int, error) {
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
	return offset, nil
}
