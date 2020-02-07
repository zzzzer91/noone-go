package user

import (
	"noone/dnscache"
	"sync"
)

type Info struct {
	Port     int
	Method   string
	Password string
	Key      []byte

	DnsCache *dnscache.Cache // Every user has own DNS cache

	lock sync.RWMutex
}
