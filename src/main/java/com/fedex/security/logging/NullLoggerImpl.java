package com.fedex.security.logging;

class NullLoggerImpl
		implements Logger {
	public void debug(Object message) {
	}

	public void debug(Object message, Throwable t) {
	}

	public void error(Object message) {
	}

	public void error(Object message, Throwable t) {
	}

	public void fatal(Object message) {
	}

	public void fatal(Object message, Throwable t) {
	}

	public void info(Object message) {
	}

	public void info(Object message, Throwable t) {
	}

	public boolean isDebugEnabled() {
		return false;
	}

	public boolean isErrorEnabled() {
		return false;
	}

	public boolean isFatalEnabled() {
		return false;
	}

	public boolean isInfoEnabled() {
		return false;
	}

	public boolean isTraceEnabled() {
		return false;
	}

	public boolean isWarnEnabled() {
		return false;
	}

	public void trace(Object message) {
	}

	public void trace(Object message, Throwable t) {
	}

	public void warn(Object message) {
	}

	public void warn(Object message, Throwable t) {
	}

	public void audit(Object message) {
	}

	public void audit(Object message, Throwable t) {
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\logging\NullLoggerImpl.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */