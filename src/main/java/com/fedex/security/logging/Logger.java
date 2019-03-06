package com.fedex.security.logging;

public interface Logger {
	void trace(Object paramObject);

	void trace(Object paramObject, Throwable paramThrowable);

	void debug(Object paramObject);

	void debug(Object paramObject, Throwable paramThrowable);

	void info(Object paramObject);

	void info(Object paramObject, Throwable paramThrowable);

	void warn(Object paramObject);

	void warn(Object paramObject, Throwable paramThrowable);

	void error(Object paramObject);

	void error(Object paramObject, Throwable paramThrowable);

	void fatal(Object paramObject);

	void fatal(Object paramObject, Throwable paramThrowable);

	void audit(Object paramObject);

	void audit(Object paramObject, Throwable paramThrowable);

	boolean isTraceEnabled();

	boolean isDebugEnabled();

	boolean isInfoEnabled();

	boolean isWarnEnabled();

	boolean isErrorEnabled();

	boolean isFatalEnabled();
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\logging\Logger.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */