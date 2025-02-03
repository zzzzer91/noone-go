package trojan

import "sync"

var trojanCtxPool *sync.Pool

func init() {
	trojanCtxPool = &sync.Pool{
		New: func() interface{} {
			return newTrojanCtx()
		},
	}
}

func getTrojanCtx() *trojanCtx {
	return trojanCtxPool.Get().(*trojanCtx)
}

func putTrojanCtx(c *trojanCtx) {
	c.reset()
	trojanCtxPool.Put(c)
}
