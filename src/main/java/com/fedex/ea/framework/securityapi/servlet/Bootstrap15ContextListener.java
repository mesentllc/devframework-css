package com.fedex.ea.framework.securityapi.servlet;

import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import com.fedex.security.bootstrap.CSSBootstrap15;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class Bootstrap15ContextListener implements ServletContextListener {
	private static final FedExLoggerInterface LOGGER = FedExLogger.getLogger(Bootstrap15ContextListener.class);

	public void contextInitialized(ServletContextEvent sce) {
	}

	public void contextDestroyed(ServletContextEvent sce) {
		LOGGER.info("Stopping threads");
		new CSSBootstrap15().cancelTimerTasks();
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\servlet\Bootstrap15ContextListener.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */