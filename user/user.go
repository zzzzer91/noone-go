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
	DnsCache *dnscache.Cache // 每个用户都创建一个 DNS 缓存
	Pool     *sync.Pool      // 对象复用池，复用 `tcp.ctx`
}
