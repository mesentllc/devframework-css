package com.fedex.security.server;

import java.util.List;

public interface GroupsCache {
	boolean memberOf(String paramString1, String paramString2);

	boolean memberOfAny(String paramString, List<String> paramList);

	List<String> getMembersOfGroup(String paramString);

	List<String> getMembersOfGroupCached(String paramString);

	List<String> getGroupsForUser(String paramString);

	List<String> getGroupsForUserCached(String paramString);

	List<String> getGroupListFromPolicy();
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\server\GroupsCache.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */