package com.fedex.security.server;

import com.fedex.security.exceptions.SecurityConfigurationException;

public final class RevocationProviderFactory {
	private static RevocationProvider provider;

	public static void configure(RevocationProvider newProvider) {
		provider = newProvider;
	}

	public static RevocationProvider getProvider()
			throws SecurityConfigurationException {
		if (provider == null) {
			String msg = "RevocationProviderFactory called before being properly configured.";
			throw new SecurityConfigurationException("RevocationProviderFactory called before being properly configured.");
		}
		return provider;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\server\RevocationProviderFactory.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */