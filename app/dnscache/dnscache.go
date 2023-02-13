// GO 自带 DNS 查询不带缓存，简单写了个带缓存的

package dnscache

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type entry struct {
	ips       []net.IP
	err       error
	refreshed bool // 一定时间内使用过则为 true
	wg        sync.WaitGroup
}

type Cache struct {
	dict               map[string]*entry
	lock               sync.Mutex
	isCleanTaskRunning bool
}

func NewCache() *Cache {
	return &Cache{
		dict: make(map[string]*entry),
	}
}

func (c *Cache) LookupIP(host string) ([]net.IP, error) {
	c.lock.Lock()
	if !c.isCleanTaskRunning {
		c.initCleanTask()
	}

	if e, ok := c.dict[host]; ok {
		e.refreshed = true
		c.lock.Unlock()
		e.wg.Wait()
		return e.ips, e.err
	}
	// 这里设为 true，保证下面执行 LookupIP 时 key 不会被 CleanTask 清理
	// 因为下面释放锁后，锁可能被 CleanTask 抢到，然后 entry 就会被清理
	e := &entry{refreshed: true}
	e.wg.Add(1)
	c.dict[host] = e
	c.lock.Unlock()
	logrus.Debug("LookupIP: " + host)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	e.ips, e.err = net.DefaultResolver.LookupIP(ctx, "ip", host)
	e.wg.Done()
	return e.ips, e.err
}

func (c *Cache) Del(key string) {
	c.lock.Lock()
	delete(c.dict, key)
	c.lock.Unlock()
}

func (c *Cache) initCleanTask() {
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for range t.C {
			c.clear()
			logrus.Debug("Clear the expired DNS caches regularly")
		}
	}()
	c.isCleanTaskRunning = true
}

func (c *Cache) clear() {
	c.lock.Lock()
	for k, v := range c.dict {
		if v.refreshed {
			v.refreshed = false
		} else {
			delete(c.dict, k)
		}
	}
	c.lock.Unlock()
}
