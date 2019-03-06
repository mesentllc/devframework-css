package com.fedex.security.server;

import com.fedex.security.exceptions.SecurityConfigurationException;

public class RestrictionCacheFactory {
	private static RestrictionCache restrictionCache = null;

	public static void setRestrictionCache(RestrictionCache rc) {
		restrictionCache = rc;
	}

	public static RestrictionCache getRestrictionCache()
			throws SecurityConfigurationException {
		if (restrictionCache == null) {
			String msg = "RestrictionCacheFactory called before being properly configured.  The restriction cache is null.";
			throw new SecurityConfigurationException("RestrictionCacheFactory called before being properly configured.  The restriction cache is null.");
		}
		return restrictionCache;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\server\RestrictionCacheFactory.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */