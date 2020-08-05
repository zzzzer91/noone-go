package tcp

import (
	"github.com/sirupsen/logrus"
	"io"
	"net"
	"noone/app/manager"
	"noone/app/user"
	"strconv"
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
		c := manager.M.TcpCtxPool.Get().(*ctx)
		c.ClientAddr = conn.RemoteAddr()
		c.clientConn = conn
		c.UserInfo = userInfo

		go handle(c)
	}
}

func handle(c *ctx) {
	defer manager.M.TcpCtxPool.Put(c)
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
		// 对端关闭，忽略
		if err == io.EOF {
			return
		}
		logrus.Error(err)
		return
	}
}
