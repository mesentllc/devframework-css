package com.fedex.security.server;

import com.fedex.security.exceptions.SecurityConfigurationException;

public class AuthorizorFactory {
	private static Authorizor authorizor = null;

	public static void setAuthorizor(Authorizor authz) {
		authorizor = authz;
	}

	public static Authorizor getAuthorizor()
			throws SecurityConfigurationException {
		if (authorizor == null) {
			String msg = "AuthorizorFactory called before being properly configured.";
			throw new SecurityConfigurationException("AuthorizorFactory called before being properly configured.");
		}
		return authorizor;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\server\AuthorizorFactory.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */