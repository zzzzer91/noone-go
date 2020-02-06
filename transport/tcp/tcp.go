package tcp

import (
	"github.com/kataras/golog"
	"io"
	"net"
	"noone/transport"
	"noone/user"
	"strconv"
	"sync"
)

func Run(userInfo *user.Info) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", ":"+strconv.Itoa(userInfo.Port))
	if err != nil {
		golog.Fatal(err)
	}
	l, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		golog.Fatal(err)
	}
	// 复用 ctx 对象，防止缓冲区不停分配，回收，也许能提高性能？
	userInfo.Pool = &sync.Pool{
		New: func() interface{} {
			return &ctx{
				Ctx: transport.Ctx{
					Network:  "tcp",
					UserInfo: userInfo,
				},
				clientBuf: make([]byte, clientBufCapacity),
				remoteBuf: make([]byte, remoteBufCapacity),
			}
		},
	}
	for {
		conn, err := l.AcceptTCP()
		if err != nil {
			golog.Error(err)
			continue
		}
		err = conn.SetKeepAlive(true)
		if err != nil {
			golog.Error(err)
			continue
		}
		go handle(userInfo, conn)
	}
}

func handle(userInfo *user.Info, conn *net.TCPConn) {
	c := userInfo.Pool.Get().(*ctx)
	c.ClientAddr = conn.RemoteAddr()
	c.clientConn = conn
	defer userInfo.Pool.Put(c)
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
