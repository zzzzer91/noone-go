// GO 自带 DNS 查询不带缓存，简单写了个带缓存的

package dnscache

import (
	"github.com/kataras/golog"
	"net"
	"sync"
)

type entry struct {
	ips     []net.IP
	refresh bool // 一定时间内使用过则为 true
}

type Cache struct {
	dict map[string]*entry // dict 可能变得很大？
	lock sync.RWMutex
}

func NewCache() *Cache {
	return &Cache{
		dict: make(map[string]*entry),
	}
}

func (c *Cache) set(key string, ips []net.IP) {
	c.lock.Lock()
	c.dict[key] = &entry{
		ips:     ips,
		refresh: false, // 设为 false，接下来一段时间不用，就会被清理
	}
	c.lock.Unlock()
}

func (c *Cache) get(key string) []net.IP {
	c.lock.RLock()
	defer c.lock.RUnlock()
	v, ok := c.dict[key]
	if !ok {
		return nil
	}
	// 这里感觉不加写锁没问题？
	v.refresh = true
	return v.ips
}

func (c *Cache) Del(key string) {
	c.lock.Lock()
	delete(c.dict, key)
	c.lock.Unlock()
}

func (c *Cache) Clear() {
	temp := make(map[string]*entry, len(c.dict))
	c.lock.Lock()
	for k, v := range c.dict {
		if v.refresh {
			v.refresh = false
			temp[k] = v
		}
	}
	c.dict = temp
	c.lock.Unlock()
}

func (c *Cache) LookupIP(host string) ([]net.IP, error) {
	if v := c.get(host); v != nil {
		golog.Debug(host + " 缓存命中")
		return v, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	c.set(host, ips)
	return ips, nil
}
