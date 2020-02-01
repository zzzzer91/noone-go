package tcp

import (
	"github.com/kataras/golog"
	"io"
	"net"
	"noone/transport"
	"sync"
)

func handle(pool *sync.Pool, conn net.Conn) {
	c := pool.Get().(*transport.Ctx)
	c.Network = "tcp"
	c.ClientConn = conn

	defer pool.Put(c)
	defer c.Reset()

	if err := c.HandleStageInit(); err != nil {
		golog.Error(err)
		return
	}
	if err := c.HandleStageParseHeader(); err != nil {
		golog.Error(err)
		return
	}
	if err := c.HandleStageHandShake(); err != nil {
		golog.Error(err)
		return
	}
	if err := c.HandleStream(); err != nil {
		// 对端关闭，忽略
		if err == io.EOF {
			return
		}
		golog.Error(err)
		return
	}
}
