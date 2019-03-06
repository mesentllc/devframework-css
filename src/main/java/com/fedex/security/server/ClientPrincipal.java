package com.fedex.security.server;

import java.security.Principal;

public final class ClientPrincipal
		implements Principal {
	private String clientId;
	private String onBehalfOf;
	private String cipherText;
	private long createTimestamp;

	private ClientPrincipal() {
	}

	ClientPrincipal(String clientId, String onBehalfOf, String cipherText, long createTimestamp) {
		this.clientId = clientId;
		this.onBehalfOf = onBehalfOf;
		this.cipherText = cipherText;
		this.createTimestamp = createTimestamp;
	}

	public final String getName() {
		return this.onBehalfOf == null ? this.clientId : this.onBehalfOf;
	}

	public final String getClientId() {
		return this.clientId;
	}

	public final String getOnBehalfOf() {
		return this.onBehalfOf;
	}

	public final String getCipherText() {
		return this.cipherText;
	}

	public final long getCreateTimestamp() {
		return this.createTimestamp;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\server\ClientPrincipal.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */