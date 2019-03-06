package com.fedex.security.server;

import com.fedex.enterprise.security.role.restriction.RestrictionData;
import com.fedex.security.exceptions.NullEntryListException;

import java.util.Map;
import java.util.Set;

public interface Authorizor {
	boolean isAllowed(String paramString1, String paramString2, String paramString3);

	boolean isAllowed(String paramString1, String paramString2, String paramString3, Map paramMap);

	Map<Permission, Boolean> isAllowed(String paramString1, Set<Permission> paramSet, String paramString2);

	Map<Permission, Boolean> isAllowed(String paramString, Set<Permission> paramSet, Map paramMap);

	Map<String, Boolean> isAllowedForAllActions(String paramString, Set<String> paramSet1, Set<String> paramSet2, Map paramMap);

	boolean isAllowed(RestrictionData paramRestrictionData, String paramString1, String paramString2, String paramString3)
			throws NullEntryListException;
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\server\Authorizor.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */