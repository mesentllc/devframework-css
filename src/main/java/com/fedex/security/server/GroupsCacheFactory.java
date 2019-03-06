package com.fedex.security.server;

import com.fedex.security.exceptions.SecurityConfigurationException;

public class GroupsCacheFactory {
	private static GroupsCache groupsCache = null;

	public static void setGroupsCache(GroupsCache gc) {
		groupsCache = gc;
	}

	public static GroupsCache getGroupsCache()
			throws SecurityConfigurationException {
		if (groupsCache == null) {
			String msg = "GroupsCacheFactory called before being properly configured.";
			throw new SecurityConfigurationException("GroupsCacheFactory called before being properly configured.");
		}
		return groupsCache;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\server\GroupsCacheFactory.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */