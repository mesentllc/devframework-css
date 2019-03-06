package com.fedex.security.logging;

import java.util.Date;

class PrintlnLoggerImpl
		implements Logger {
	public void debug(Object message) {
		System.out.println(new Date() + " - DEBUG : " + message);
	}

	public void debug(Object message, Throwable t) {
		System.out.println(new Date() + " - DEBUG : " + message);
		System.out.println(t.getStackTrace() + "\n");
	}

	public void error(Object message) {
		System.err.println(new Date() + " - ERROR : " + message);
	}

	public void error(Object message, Throwable t) {
		System.err.println(new Date() + " - ERROR : " + message);
		System.err.println(t.getStackTrace() + "\n");
	}

	public void fatal(Object message) {
		System.err.println(new Date() + " - FATAL : " + message);
	}

	public void fatal(Object message, Throwable t) {
		System.err.println(new Date() + " - FATAL : " + message);
		System.err.println(t.getStackTrace() + "\n");
	}

	public void info(Object message) {
		System.out.println(new Date() + " - INFO : " + message);
	}

	public void info(Object message, Throwable t) {
		System.out.println(new Date() + " - INFO : " + message);
		System.out.println(t.getStackTrace() + "\n");
	}

	public boolean isDebugEnabled() {
		return true;
	}

	public boolean isErrorEnabled() {
		return true;
	}

	public boolean isFatalEnabled() {
		return true;
	}

	public boolean isInfoEnabled() {
		return true;
	}

	public boolean isTraceEnabled() {
		return true;
	}

	public boolean isWarnEnabled() {
		return true;
	}

	public void trace(Object message) {
		System.out.println(new Date() + " - TRACE: " + message);
	}

	public void trace(Object message, Throwable t) {
		System.out.println(new Date() + " - TRACE: " + message);
		System.out.println(t.getStackTrace() + "\n");
	}

	public void warn(Object message) {
		System.out.println(new Date() + " - WARN: " + message);
	}

	public void warn(Object message, Throwable t) {
		System.out.println(new Date() + " - WARN: " + message);
		System.out.println(t.getStackTrace() + "\n");
	}

	public void audit(Object message) {
		System.out.println(new Date() + " - AUDIT: " + message);
	}

	public void audit(Object message, Throwable t) {
		System.out.println(new Date() + " - AUDIT: " + message);
		System.out.println(t.getStackTrace() + "\n");
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\logging\PrintlnLoggerImpl.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */