package manager

import (
	"noone/user"
	"sync"
)

type Manager struct {
	Users []*user.User
	// NewUser    chan *user.User // wait for the new user
	UsedPorts  map[int]struct{}
	TcpCtxPool *sync.Pool // reuse the tcp.ctx object
}

var M = &Manager{
	// NewUser:   make(chan *user.User),
	UsedPorts: make(map[int]struct{}),
}
