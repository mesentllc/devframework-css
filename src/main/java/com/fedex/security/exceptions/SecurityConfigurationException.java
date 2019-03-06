package com.fedex.security.exceptions;

public final class SecurityConfigurationException
		extends RuntimeException {
	public SecurityConfigurationException() {
	}

	public SecurityConfigurationException(String message) {
		super(message);
	}

	public SecurityConfigurationException(Throwable cause) {
		super(cause);
	}

	public SecurityConfigurationException(String message, Throwable cause) {
		super(message, cause);
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\exceptions\SecurityConfigurationException.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */