package com.fedex.security.bootstrap;

import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import com.fedex.security.client.ClientCipherProviderFactory;
import com.fedex.security.client.KeystoreCipherProviderImpl;
import com.fedex.security.client.PkcTokenGeneratorImpl;
import com.fedex.security.client.TokenGenerator;
import com.fedex.security.server.AuthorizorFactory;
import com.fedex.security.server.AuthorizorImpl;
import com.fedex.security.server.GroupsCacheFactory;
import com.fedex.security.server.GroupsCacheGroupMajorListImpl;
import com.fedex.security.server.LdapCipherProviderImpl;
import com.fedex.security.server.PkcTokenAuthenticatorImpl;
import com.fedex.security.server.RevocationProviderFactory;
import com.fedex.security.server.RolesCacheFactory;
import com.fedex.security.server.RolesCacheFileImpl;
import com.fedex.security.server.RulesCacheFactory;
import com.fedex.security.server.RulesCacheFileImpl;
import com.fedex.security.server.ServerCipherProviderFactory;

public class CSSBootstrap {
	private static final long serialVersionUID = 1L;
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(CSSBootstrap.class.getName());
	private String clientProperties = "client.properties";
	private String securityProperties = "security.properties";

	public void setClientProperties(String clientProperties) {
		this.clientProperties = clientProperties;
		logger.debug(new FedExLogEntry("...Set clientProperties to " + clientProperties + "..."));
	}

	public void setSecurityProperties(String securityProperties) {
		this.securityProperties = securityProperties;
		logger.debug(new FedExLogEntry("...Set securityProperties to " + securityProperties + "..."));
	}

	public CSSBootstrap() {
		defaultClientConfig();
	}

	public CSSBootstrap(boolean isClient, boolean isService, String clientProperties, String securityProperties) {
		try {
			logger.debug(new FedExLogEntry("...Initializing CSS Bootstrap..."));
			if (isClient) {
				logger.debug(new FedExLogEntry("...Configuring Client Functionality..."));
				clientConfig(clientProperties, securityProperties);
			}
			if (isService) {
				logger.debug(new FedExLogEntry("...Configuring Service Functionality..."));
				serviceConfig(securityProperties);
			}
			logger.debug(new FedExLogEntry("...CSS Bootstrap Completed..."));
		}
		catch (Exception e) {
			logger.fatal(new FedExLogEntry("!!!!!!!!!Error Starting Bootstrap!!!!!!!!!  "));
			e.printStackTrace();
			throw new RuntimeException("!!Error Starting Common Security Service Bootstrap!!", e);
		}
	}

	public void defaultClientConfig() {
		ClientCipherProviderFactory.configure(KeystoreCipherProviderImpl.getInstance());
		TokenGenerator gen = PkcTokenGeneratorImpl.getInstance();
		gen.configure();
	}

	public void clientConfig(String clientProperties, String securityProperties) {
		ClientCipherProviderFactory.configure(KeystoreCipherProviderImpl.getInstance(securityProperties));
		TokenGenerator gen = PkcTokenGeneratorImpl.getInstance(securityProperties);
		gen.configure(clientProperties);
	}

	public void defaultServiceConfig() {
		ServerCipherProviderFactory.configure(LdapCipherProviderImpl.getInstance());
		RevocationProviderFactory.configure(LdapCipherProviderImpl.getInstance());
		RulesCacheFileImpl rulesCache = RulesCacheFileImpl.getInstance();
		rulesCache.configure();
		RulesCacheFactory.setRulesCache(rulesCache);
		RolesCacheFileImpl rolesCache = RolesCacheFileImpl.getInstance();
		rolesCache.configure();
		RolesCacheFactory.setRolesCache(rolesCache);
		GroupsCacheGroupMajorListImpl groupsCache = GroupsCacheGroupMajorListImpl.getInstance();
		groupsCache.cache(RolesCacheFactory.getRolesCache().getRoles());
		GroupsCacheFactory.setGroupsCache(groupsCache);
		AuthorizorFactory.setAuthorizor(new AuthorizorImpl());
	}

	public void serviceConfig(String securityProperties) {
		ServerCipherProviderFactory.configure(LdapCipherProviderImpl.getInstance(securityProperties));
		RevocationProviderFactory.configure(LdapCipherProviderImpl.getInstance(securityProperties));
		PkcTokenAuthenticatorImpl.getInstance(securityProperties);
		RulesCacheFileImpl rulesCache = RulesCacheFileImpl.getInstance();
		rulesCache.configure();
		RulesCacheFactory.setRulesCache(rulesCache);
		RolesCacheFileImpl rolesCache = RolesCacheFileImpl.getInstance();
		rolesCache.configure();
		RolesCacheFactory.setRolesCache(rolesCache);
		GroupsCacheGroupMajorListImpl groupsCache = GroupsCacheGroupMajorListImpl.getInstance(securityProperties);
		groupsCache.cache(RolesCacheFactory.getRolesCache().getRoles());
		GroupsCacheFactory.setGroupsCache(groupsCache);
		AuthorizorFactory.setAuthorizor(new AuthorizorImpl());
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\bootstrap\CSSBootstrap.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */