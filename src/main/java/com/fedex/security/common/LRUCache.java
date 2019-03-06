package com.fedex.security.common;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

public class LRUCache<K, V> {
	private int maxCacheSize;
	private Map<K, V> cache;

	public LRUCache(int maxCacheSize) {
		this.maxCacheSize = maxCacheSize;
		float loadFactor = 0.75F;
		int capacity = (int)Math.ceil(maxCacheSize / loadFactor) + 1;
		this.cache = new LinkedHashMap(capacity, loadFactor, true);
	}

	public synchronized boolean containsKey(K key) {
		return this.cache.containsKey(key);
	}

	public synchronized void put(K key, V value) {
		this.cache.put(key, value);
	}

	public synchronized V get(K key) {
		return this.cache.get(key);
	}

	public synchronized Collection<Map.Entry<K, V>> getAll() {
		return new ArrayList(this.cache.entrySet());
	}
}
