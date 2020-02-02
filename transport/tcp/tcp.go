package tcp

import (
	"github.com/kataras/golog"
	"net"
	"sync"
)

func Run(addr string) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		golog.Fatal(err)
	}
	pool := &sync.Pool{
		New: func() interface{} {
			return newCtx()
		},
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			golog.Error(err)
			continue
		}
		golog.Debug("TCP accept ", conn.RemoteAddr())
		go handle(pool, conn)
	}
}
