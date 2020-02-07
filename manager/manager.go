package manager

import (
	"noone/user"
)

type Manager struct {
	Users     []*user.User
	NewUser   chan *user.User
	UsedPorts map[int]struct{}
}

var M *Manager

func init() {
	m := Manager{
		Users:     nil,
		NewUser:   make(chan *user.User),
		UsedPorts: make(map[int]struct{}),
	}
	M = &m
}
