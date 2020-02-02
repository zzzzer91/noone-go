package tcp

import (
	"github.com/kataras/golog"
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
		golog.Debug("TCP accept ", conn.RemoteAddr())
		go handle(pool, conn)
	}
}
