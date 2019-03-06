package com.fedex.security.server;

import com.fedex.security.exceptions.SecurityConfigurationException;

public class RolesCacheFactory {
	private static RolesCache rolesCache = null;

	public static void setRolesCache(RolesCache rc) {
		rolesCache = rc;
	}

	public static RolesCache getRolesCache()
			throws SecurityConfigurationException {
		if (rolesCache == null) {
			String msg = "RolesCacheFactory called before being properly configured.";
			throw new SecurityConfigurationException("RolesCacheFactory called before being properly configured.");
		}
		return rolesCache;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\server\RolesCacheFactory.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */