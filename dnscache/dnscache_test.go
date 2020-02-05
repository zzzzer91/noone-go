package dnscache

import "testing"

func TestClearCache(t *testing.T) {
	// 不要调用 `defaultDnsCache.get()` 获取缓存，`get()` 中有刷新条目逻辑

	url := "www.baidu.com"
	// 第一次查询，缓存没有，调用 set，refresh 为 false
	_, err := LookupIP(url)
	if err != nil {
		t.Fatal(err)
	}
	if v := defaultDnsCache.cache[url]; v == nil || v.ips == nil || v.refresh {
		t.Fatal("get error")
	}

	// 第二次查询，发现缓存已有，则会使用缓存，并刷新条目，refresh 为 true
	_, err = LookupIP(url)
	if err != nil {
		t.Fatal(err)
	}
	if v := defaultDnsCache.cache[url]; v == nil || v.ips == nil || !v.refresh {
		t.Fatal("get refresh error")
	}
	if len(defaultDnsCache.cache) != 1 {
		t.Fatal("clear error")
	}

	// 把有 refresh 为 true 条目置为 false
	defaultDnsCache.clear()
	if v := defaultDnsCache.cache[url]; v == nil || v.ips == nil || v.refresh {
		t.Fatal("clear set refresh error")
	}

	// 清除所有 false 条目
	defaultDnsCache.clear()
	if v := defaultDnsCache.cache[url]; v != nil {
		t.Fatal("clear error")
	}
	if len(defaultDnsCache.cache) != 0 {
		t.Fatal("clear error")
	}
}
