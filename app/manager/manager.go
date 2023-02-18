package manager

import (
	"noone/app/config"
	"noone/app/dnscache"
)

type Manager struct {
	UsedPorts map[int]struct{}
	DnsCache  *dnscache.Cache
	Proxies   []*Proxy
}

var M = &Manager{
	UsedPorts: make(map[int]struct{}),
	DnsCache:  dnscache.NewCache(),
}

func Init(conf *config.Conf) {
	M = &Manager{
		UsedPorts: make(map[int]struct{}),
		DnsCache:  dnscache.NewCache(),
		Proxies:   initProxies(conf),
	}
}
