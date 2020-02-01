package tcp

import (
	"github.com/kataras/golog"
	"net"
	"sync"
)

func Run(pool *sync.Pool, addr string) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		golog.Fatal(err)
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
