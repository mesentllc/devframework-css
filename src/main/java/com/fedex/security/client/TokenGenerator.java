package com.fedex.security.client;

public interface TokenGenerator {
	void configure();

	void configure(String paramString);

	void configure(String paramString1, String paramString2);

	boolean isConfigured(String paramString);

	String getTokenForClientId(String paramString1, String paramString2, String paramString3);

	String getTokenForClientId(String paramString1, String paramString2, String paramString3, boolean paramBoolean);

	String getToken(String paramString1, String paramString2);

	String getToken(String paramString1, String paramString2, boolean paramBoolean);

	String getTokenForClientId(String paramString1, String paramString2);

	String getTokenForClientId(String paramString1, String paramString2, boolean paramBoolean);

	String getToken(String paramString);

	String getToken(String paramString, boolean paramBoolean);

	String getChainedToken(String paramString1, String paramString2);

	String getChainedToken(String paramString1, String paramString2, boolean paramBoolean);

	String getChainedTokenForClientId(String paramString1, String paramString2, String paramString3);

	String getChainedTokenForClientId(String paramString1, String paramString2, String paramString3, boolean paramBoolean);
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\client\TokenGenerator.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */