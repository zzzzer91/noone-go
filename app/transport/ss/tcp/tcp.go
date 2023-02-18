package tcp

import (
	"net"
	"noone/app/user"
	"strconv"

	"github.com/sirupsen/logrus"
)

func Run(userInfo *user.User) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", userInfo.Server+":"+strconv.Itoa(userInfo.Port))
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
		c.UserInfo = userInfo

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
