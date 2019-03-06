package com.fedex.security.server;

import java.util.List;
import java.util.Set;

public interface RolesCache {
	Role getRole(String paramString);

	Set<Role> getRoles();

	Set<String> getRoleNames();

	List<String> getRolesForUser(String paramString);

	void triggerUpdate();

	List<String> getGroupsForRole(String paramString);
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\server\RolesCache.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */