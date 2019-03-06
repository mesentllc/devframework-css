package com.fedex.security.client;

import java.io.Serializable;

public class CryptoException
		extends Exception
		implements Serializable {
	public static final long serialVersionUID = 314160L;

	public CryptoException() {
	}

	public CryptoException(String msg) {
		super(msg);
	}

	public CryptoException(String msg, Throwable cause) {
		super(msg, cause);
	}

	public CryptoException(Throwable cause) {
		super(cause);
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\client\CryptoException.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */