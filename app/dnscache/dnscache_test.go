package dnscache

import "testing"

func TestClearCache(t *testing.T) {
	// 不要调用 `cache.get()` 获取缓存，`get()` 中有刷新条目逻辑
	cache := NewCache()

	url := "www.baidu.com"
	// 第一次查询，缓存没有，调用 set，refresh 为 false
	_, err := cache.LookupIP(url)
	if err != nil {
		t.Fatal(err)
	}
	if v := cache.dict[url]; v == nil || v.ips == nil || v.refresh {
		t.Fatal("get error")
	}

	// 第二次查询，发现缓存已有，则会使用缓存，并刷新条目，refresh 为 true
	_, err = cache.LookupIP(url)
	if err != nil {
		t.Fatal(err)
	}
	if v := cache.dict[url]; v == nil || v.ips == nil || !v.refresh {
		t.Fatal("get refresh error")
	}
	if len(cache.dict) != 1 {
		t.Fatal("clear error")
	}

	// 把有 refresh 为 true 条目置为 false
	cache.Clear()
	if v := cache.dict[url]; v == nil || v.ips == nil || v.refresh {
		t.Fatal("clear set refresh error")
	}

	// 清除所有 false 条目
	cache.Clear()
	if v := cache.dict[url]; v != nil {
		t.Fatal("clear error")
	}
	if len(cache.dict) != 0 {
		t.Fatal("clear error")
	}
}
