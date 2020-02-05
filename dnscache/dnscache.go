// GO 自带 DNS 查询不带缓存，简单写了个带缓存的

package dnscache

import (
	"github.com/kataras/golog"
	"net"
	"sync"
	"time"
)

const (
	clearInterval = 5 * time.Minute
)

type entry struct {
	ips     []net.IP
	refresh bool // 一定时间内使用过则为 true
}

type dnsCache struct {
	cache map[string]*entry // cache 可能变得很大？
	lock  sync.RWMutex
}

func (l *dnsCache) set(key string, val *entry) {
	l.lock.Lock()
	l.cache[key] = val
	l.lock.Unlock()
}

func (l *dnsCache) get(key string) *entry {
	l.lock.RLock()
	v, ok := l.cache[key]
	l.lock.RUnlock()
	if !ok {
		return nil
	}
	// 这里感觉不加锁没问题？
	v.refresh = true
	return v
}

func (l *dnsCache) del(key string) {
	l.lock.Lock()
	delete(l.cache, key)
	l.lock.Unlock()
}

func (l *dnsCache) clear() {
	temp := make(map[string]*entry, len(l.cache))
	l.lock.Lock()
	for k, v := range l.cache {
		if v.refresh {
			v.refresh = false
			temp[k] = v
		}
	}
	l.cache = temp
	l.lock.Unlock()
}

var defaultDnsCache = &dnsCache{
	cache: make(map[string]*entry),
}

func init() {
	// 开个协程定时清理
	go func() {
		time.Sleep(clearInterval)
		golog.Debug("定时清理 DNS 缓存")
		defaultDnsCache.clear()
	}()
}

func LookupIP(host string) ([]net.IP, error) {
	if v := defaultDnsCache.get(host); v != nil {
		return v.ips, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	defaultDnsCache.set(host, &entry{
		ips:     ips,
		refresh: false, // 设为 false，接下来一段时间不用，就会被清理
	})
	return ips, nil
}
