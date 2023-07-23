package manager

import (
	"github.com/zzzzer91/noone/internal/config"
	"github.com/zzzzer91/noone/internal/dnscache"
)

type Manager struct {
	UsedPorts map[int]struct{}
	DnsCache  *dnscache.Cache
}

var M = &Manager{
	UsedPorts: make(map[int]struct{}),
	DnsCache:  dnscache.NewCache(),
}

func Init(conf *config.Conf) {
	M = &Manager{
		UsedPorts: make(map[int]struct{}),
		DnsCache:  dnscache.NewCache(),
	}
}
