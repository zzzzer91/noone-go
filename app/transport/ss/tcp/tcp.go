package tcp

import (
	"net"
	"noone/app/manager"
	"strconv"

	"github.com/sirupsen/logrus"
)

func Run(proxy *manager.Proxy) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", proxy.Server+":"+strconv.Itoa(proxy.Port))
	if err != nil {
		logrus.Fatal(err)
	}
	l, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		logrus.Fatal(err)
	}
	for {
		conn, err := l.AcceptTCP()
		if err != nil {
			logrus.Error(err)
			continue
		}
		if err := conn.SetKeepAlive(true); err != nil {
			logrus.Error(err)
			return
		}

		c := tcpCtxPool.Get().(*ctx)
		c.ClientAddr = conn.RemoteAddr()
		c.clientConn = conn
		c.UserInfo = proxy

		go handle(c)
	}
}

func handle(c *ctx) {
	defer tcpCtxPool.Put(c)
	defer c.reset()

	logrus.Debug("TCP accept " + c.ClientAddr.String())

	if err := c.handleStageInit(); err != nil {
		logrus.Error(err)
		return
	}

	if err := c.handleStageHandShake(); err != nil {
		logrus.Error(err)
		return
	}

	if err := c.handleStageStream(); err != nil {
		logrus.Error(err)
		return
	}
}
