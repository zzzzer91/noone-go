package tcp

import (
	"github.com/kataras/golog"
	"io"
	"net"
	"sync"
)

func handle(pool *sync.Pool, conn net.Conn) {
	c := pool.Get().(*ctx)
	c.clientConn = conn

	defer pool.Put(c)
	defer c.reset()

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
