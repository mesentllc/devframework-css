package com.fedex.security.server;

import com.fedex.security.common.CipherProvider;
import com.fedex.security.exceptions.SecurityConfigurationException;

public final class ServerCipherProviderFactory {
	private static CipherProvider provider;

	public static void configure(CipherProvider newProvider) {
		provider = newProvider;
	}

	public static CipherProvider getProvider()
			throws SecurityConfigurationException {
		if (provider == null) {
			String msg = "ServerCipherProviderFactory called before being properly configured.";
			throw new SecurityConfigurationException("ServerCipherProviderFactory called before being properly configured.");
		}
		return provider;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\server\ServerCipherProviderFactory.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */