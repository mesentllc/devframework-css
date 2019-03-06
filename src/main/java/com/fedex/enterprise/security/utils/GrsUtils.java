package com.fedex.enterprise.security.utils;

import com.fedex.security.server.GroupsCache;
import com.fedex.security.server.GroupsCacheFactory;

import java.util.List;

public class GrsUtils {
	LDAPSearch ldapSearch;

	public LDAPSearch getLdapSearch() {
		return this.ldapSearch;
	}

	public void setLdapSearch(LDAPSearch ldapSearch) {
		this.ldapSearch = ldapSearch;
	}

	public List<String> getMembersOfGroup(String groupNm) {
		GroupsCache groupCache = GroupsCacheFactory.getGroupsCache();
		return groupCache.getMembersOfGroup(groupNm);
	}

	public List<String> getGroupsForUser(String userId) {
		GroupsCache groupCache = GroupsCacheFactory.getGroupsCache();
		return groupCache.getGroupsForUser(userId);
	}
}
