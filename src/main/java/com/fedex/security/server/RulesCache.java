package com.fedex.security.server;

import java.util.List;
import java.util.Map;

public interface RulesCache {
	List<Rule> getRules(String paramString1, String paramString2);

	List<Rule> getGrantRules(String paramString1, String paramString2, Map<?, ?> paramMap);

	List<Rule> getDenyRules(String paramString1, String paramString2, Map<?, ?> paramMap);

	List<Long> getRoleDocIds();
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\server\RulesCache.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */