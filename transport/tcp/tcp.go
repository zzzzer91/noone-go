package tcp

import (
	"github.com/kataras/golog"
	"io"
	"net"
	"noone/manager"
	"noone/user"
	"strconv"
)

func Run(userInfo *user.User) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", userInfo.Server+":"+strconv.Itoa(userInfo.Port))
	if err != nil {
		golog.Fatal(err)
	}
	l, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		golog.Fatal(err)
	}
	for {
		conn, err := l.AcceptTCP()
		if err != nil {
			golog.Error(err)
			continue
		}

		if err := conn.SetKeepAlive(true); err != nil {
			golog.Error(err)
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

	golog.Debug("TCP accept " + c.ClientAddr.String())
	if err := c.handleStageInit(); err != nil {
		golog.Error(err)
		return
	}
	if err := c.handleStageHandShake(); err != nil {
		golog.Error(err)
		return
	}
	if err := c.handleStream(); err != nil {
		// 对端关闭，忽略
		if err == io.EOF {
			return
		}
		golog.Error(err)
		return
	}
}
