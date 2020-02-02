package tcp

import (
	"github.com/kataras/golog"
	"io"
	"net"
	"sync"
)

func Run(addr string) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		golog.Fatal(err)
	}
	l, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		golog.Fatal(err)
	}
	pool := &sync.Pool{
		New: func() interface{} {
			return newCtx()
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
		go handle(pool, conn)
	}
}

func handle(pool *sync.Pool, conn *net.TCPConn) {
	c := pool.Get().(*ctx)
	c.ClientAddr = conn.RemoteAddr().String()
	c.clientConn = conn
	defer pool.Put(c)
	defer c.reset()

	golog.Debug("TCP accept ", c.ClientAddr)
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
