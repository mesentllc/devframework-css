package com.fedex.security.client;

import com.fedex.security.common.CipherProvider;
import com.fedex.security.exceptions.SecurityConfigurationException;

public final class ClientCipherProviderFactory {
	private static CipherProvider provider;

	public static void configure(CipherProvider newProvider) {
		provider = newProvider;
	}

	public static CipherProvider getProvider()
			throws SecurityConfigurationException {
		if (provider == null) {
			String msg = "ClientCipherProviderFactory called before being properly configured.";
			throw new SecurityConfigurationException("ClientCipherProviderFactory called before being properly configured.");
		}
		return provider;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\client\ClientCipherProviderFactory.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */