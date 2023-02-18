package trojan

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"noone/app/config"
	"time"

	"github.com/sirupsen/logrus"
)

func Run(p *config.Proxy) {
	conf := convertTrojanConf(p)
	tlsConf := generateTLSConfig(conf.cn, conf.alpn)
	l, err := tls.Listen("tcp", conf.addr, tlsConf)
	if err != nil {
		logrus.Fatal(err)
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			logrus.Error(err)
			continue
		}
		if err := conn.(*tls.Conn).NetConn().(*net.TCPConn).SetKeepAlive(true); err != nil {
			logrus.Error(err)
			return
		}
		c := tcpCtxPool.Get().(*tcpCtx)
		c.clientAddr = conn.RemoteAddr()
		c.clientConn = conn.(*tls.Conn)
		c.conf = conf
		go handleClientConn(c)
	}
}

func handleClientConn(c *tcpCtx) {
	defer tcpCtxPool.Put(c)
	defer c.reset()

	logrus.Debug("TCP accept " + c.clientAddr.String())

	c.clientBufIdx = 0
	c.clientBufLen = 0
	offset := 0
	for c.clientBufLen <= 66 {
		n, err := c.clientConn.Read(c.clientBuf[offset:])
		if err != nil {
			logrus.Error(err)
			return
		}
		offset += n
		c.clientBufLen += n
	}
	if !bytes.Equal(c.clientBuf[:56], c.conf.hexPassword) {
		logrus.Error("password not equal")
		return
	}
	c.clientBufIdx += 58
	cmd := c.clientBuf[c.clientBufIdx]
	if cmd != commandTCP && cmd != commandUDP {
		logrus.Error("cmd is invalid")
		return
	}
	c.clientBufIdx += 1
	var err error
	offset, err = c.parseHeader(c.clientBuf[c.clientBufIdx:])
	if err != nil {
		logrus.Error(err)
		return
	}
	c.clientBufIdx += offset + 2
	if c.remoteDomain != "" {
		c.info = fmt.Sprintf("%s:%d (%s)", c.remoteDomain, c.remotePort, c.remoteAddr.String())
	} else {
		c.info = c.remoteAddr.String()
	}

	logrus.Debug("Connecting " + c.info)
	conn, err := net.DialTimeout("tcp", c.remoteAddr.(*net.TCPAddr).String(), time.Second*5)
	if err != nil {
		err = errors.New("Connect " + c.info + " error: " + err.Error())
		logrus.Error(err)
		return
	}
	c.remoteConn = conn.(*net.TCPConn)
	err = c.remoteConn.SetKeepAlive(true)
	if err != nil {
		logrus.Error(err)
		return
	}
	logrus.Info("Connected " + c.info)

	done := make(chan struct{})

	go func() {
		for {
			if err := c.readRemote(); err != nil {
				if err != io.EOF {
					logrus.Error(c.info + " readRemote err: " + err.Error())
				}
				break
			}
			if err := c.writeClient(); err != nil {
				logrus.Error(c.info + " writeClient err: " + err.Error())
				break
			}
		}
		_ = c.clientConn.CloseWrite()
		close(done)
	}()

	for {
		if err := c.writeRemote(); err != nil {
			logrus.Error(c.info + " writeRemote err: " + err.Error())
			break
		}
		if err := c.readClient(); err != nil {
			if err != io.EOF {
				logrus.Error(c.info + " readClient err: " + err.Error())
			}
			break
		}
	}
	_ = c.remoteConn.CloseWrite()
	<-done
	logrus.Debug(c.info + " tunnel closed")
}
