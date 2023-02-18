package ss

import "sync"

var tcpCtxPool *sync.Pool

func init() {
	tcpCtxPool = &sync.Pool{
		New: func() interface{} {
			return newTcpCtx()
		},
	}
}
