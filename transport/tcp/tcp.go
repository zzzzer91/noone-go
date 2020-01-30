package tcp

import (
	"fmt"
	"github.com/kataras/golog"
	"net"
	"noone/conf"
	"noone/transport"
	"sync"
)

func Run() {
	address := fmt.Sprintf("%s:%d", conf.S.Server, conf.S.ServerPort)
	l, err := net.Listen("tcp", address)
	if err != nil {
		golog.Fatal(err)
	}
	pool := sync.Pool{
		New: func() interface{} {
			return transport.New()
		},
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			golog.Error(err)
			continue
		}
		golog.Debug("TCP accept: ", conn.RemoteAddr())
		go handle(&pool, conn)
	}
}
