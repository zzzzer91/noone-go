package manager

import (
	"noone/app/dnscache"
	"noone/app/user"
)

type Manager struct {
	// NewUser    chan *user.User // wait for the new user
	UsedPorts map[int]struct{}
	DnsCache  *dnscache.Cache
	Users     []*user.User
}

var M = &Manager{
	// NewUser:   make(chan *user.User),
	UsedPorts: make(map[int]struct{}),
	DnsCache:  dnscache.NewCache(),
}
