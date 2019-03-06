package com.fedex.security.logging;

public class LoggerFactory {
	public static final String LOGGING_IMPL_PROP = "security.logger.impl";
	private static Logger instance = null;

	public static final synchronized Logger getLogger() {
		if (instance != null) {
			return instance;
		}
		String loggerImplName;
		if ((loggerImplName = System.getProperty("security.logger.impl")) != null) {
			try {
				System.out.println("Initializing logging using " + loggerImplName);
				instance = (Logger)Class.forName(System.getProperty("security.logger.impl")).newInstance();
			}
			catch (Exception e) {
				throw new RuntimeException("Exception creating logger implementation using class: " + loggerImplName + ", verify class name provided for " + "security.logger.impl", e);
			}
		}
		else {
			throw new RuntimeException("Exception creating logger implementation, property security.logger.impl not set.");
		}
		return instance;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\logging\LoggerFactory.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */