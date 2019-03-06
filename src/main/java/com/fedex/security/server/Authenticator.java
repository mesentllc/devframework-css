package com.fedex.security.server;

import com.fedex.security.exceptions.AuthenticationFailureException;

import java.security.Principal;

public interface Authenticator {
	Principal authenticate(String paramString1, String paramString2)
			throws AuthenticationFailureException;

	int currentClientCacheSizeForService(String paramString);
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\server\Authenticator.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */