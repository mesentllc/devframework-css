package com.fedex.security.server;

import com.fedex.enterprise.security.role.restriction.RestrictionData;
import com.fedex.security.common.FileLoader;

import java.io.File;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class ReadRestrictionCache {
	static String localCacheDir = "C:\\var\\fedex\\esc\\data\\framework\\security\\lkg\\";

	public static void main(String[] args) {
		System.out.println("------------- Reading Restriction Cache");
		readCache();
	}

	private static void readCache() {
		FileLoader localLoader = new FileLoader();
		String DISK_CACHE_FILE = "RestrctionCache.cache";
		Map<String, RestrictionData> cache = new ConcurrentHashMap();
		Object fromDisk = localLoader.readObjectFromDisk(localCacheDir + File.separator + DISK_CACHE_FILE);
		if ((fromDisk != null) && ((fromDisk instanceof Map))) {
			Map<String, RestrictionData> cacheFromDisk = (Map)fromDisk;
			if ((cacheFromDisk != null) && (cacheFromDisk.size() > 0)) {
				System.out.println("Restrictions  " + cacheFromDisk.toString());
			}
			Set<String> roleNames = new HashSet(cacheFromDisk.keySet());
			Iterator<String> roleNamesIterator = roleNames.iterator();
			int i = 1;
			while (roleNamesIterator.hasNext()) {
				String roleName = roleNamesIterator.next();
				RestrictionData roleData = cacheFromDisk.get(roleName);
				System.out.println("Restriction Data  " + roleData.toString());
			}
		}
		System.out.println("Restriction cache size: " + cache.size());
	}

	private static Map<String, RestrictionData> getRestrictionCache() {
		FileLoader localLoader = new FileLoader();
		String DISK_CACHE_FILE = "RestrctionCache.cache";
		Map<String, RestrictionData> cache = new ConcurrentHashMap();
		Object fromDisk = localLoader.readObjectFromDisk(localCacheDir + File.separator + DISK_CACHE_FILE);
		if ((fromDisk != null) && ((fromDisk instanceof Map))) {
			Map<String, RestrictionData> cacheFromDisk = (Map)fromDisk;
			if ((cacheFromDisk != null) && (cacheFromDisk.size() > 0)) {
				cache.putAll(cacheFromDisk);
			}
			cacheFromDisk = null;
		}
		return cache;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\server\ReadRestrictionCache.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */