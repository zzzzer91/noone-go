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
