package ss

import "sync"

var (
	tcpCtxPool *sync.Pool
	udpCtxPool *sync.Pool
)

func init() {
	tcpCtxPool = &sync.Pool{
		New: func() interface{} {
			return newSsTcpCtx()
		},
	}
	udpCtxPool = &sync.Pool{
		New: func() interface{} {
			return newSsUdpCtx()
		},
	}
}
