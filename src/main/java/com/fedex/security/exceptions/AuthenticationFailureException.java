package com.fedex.security.exceptions;

public final class AuthenticationFailureException
		extends Exception {
	private ReasonCode reason;

	public AuthenticationFailureException() {
	}

	public enum ReasonCode {
		INVALID_CLIENT,
		CLIENT_MISMATCH,
		SERVICE_MISMATCH,
		EXPIRED_TOKEN,
		CLIENT_REVOKED,
		GENERAL_FAILURE,
		API_ERROR;

		ReasonCode() {
		}
	}

	public AuthenticationFailureException(String message) {
		super(message);
		this.reason = ReasonCode.GENERAL_FAILURE;
	}

	public AuthenticationFailureException(ReasonCode reason, String message) {
		super(message);
		this.reason = reason;
	}

	public AuthenticationFailureException(ReasonCode reason, String message, Throwable cause) {
		super(message, cause);
		this.reason = reason;
	}

	public AuthenticationFailureException(Throwable cause) {
		super(cause);
		this.reason = ReasonCode.GENERAL_FAILURE;
	}

	public AuthenticationFailureException(String message, Throwable cause) {
		super(message, cause);
		this.reason = ReasonCode.GENERAL_FAILURE;
	}

	public ReasonCode getReasonCode() {
		return this.reason;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\exceptions\AuthenticationFailureException.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */