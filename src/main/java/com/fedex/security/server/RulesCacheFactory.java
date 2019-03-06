package com.fedex.security.server;

import com.fedex.security.exceptions.SecurityConfigurationException;

public class RulesCacheFactory {
	private static RulesCache rulesCache = null;

	public static void setRulesCache(RulesCache rc) {
		rulesCache = rc;
	}

	public static RulesCache getRulesCache()
			throws SecurityConfigurationException {
		if (rulesCache == null) {
			String msg = "RulesCacheFactory called before being properly configured.";
			throw new SecurityConfigurationException("RulesCacheFactory called before being properly configured.");
		}
		return rulesCache;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\server\RulesCacheFactory.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */