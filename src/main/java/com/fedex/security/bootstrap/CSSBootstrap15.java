package com.fedex.security.bootstrap;

import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import com.fedex.framework.utility.FedExAppFrameworkProperties;
import com.fedex.security.client.ClientCipherProviderFactory;
import com.fedex.security.client.KeystoreCipherProviderImpl;
import com.fedex.security.client.PkcTokenGeneratorImpl;
import com.fedex.security.client.TokenGenerator;
import com.fedex.security.common.FileLoader;
import com.fedex.security.server.AuthorizorEnterpriseImpl;
import com.fedex.security.server.AuthorizorFactory;
import com.fedex.security.server.AuthorizorImpl;
import com.fedex.security.server.GroupsCacheFactory;
import com.fedex.security.server.GroupsCacheGroupMajorListImpl;
import com.fedex.security.server.LdapCipherProviderImpl;
import com.fedex.security.server.PkcTokenAuthenticatorImpl;
import com.fedex.security.server.RestrictionCache;
import com.fedex.security.server.RestrictionCacheFactory;
import com.fedex.security.server.RestrictionCacheImpl;
import com.fedex.security.server.RevocationProviderFactory;
import com.fedex.security.server.RolesCacheEnterpriseImpl;
import com.fedex.security.server.RolesCacheFactory;
import com.fedex.security.server.RolesCacheFileImpl;
import com.fedex.security.server.RulesCacheEnterpriseImpl;
import com.fedex.security.server.RulesCacheFactory;
import com.fedex.security.server.RulesCacheFileImpl;
import com.fedex.security.server.ServerCipherProviderFactory;
import com.fedex.security.utils.SecurityUtils;
import org.springframework.core.io.ClassPathResource;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.Properties;

public class CSSBootstrap15 {
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(CSSBootstrap15.class.getName());
	private String clientProperties = "client.properties";
	private String securityProperties = "security.properties";
	private boolean client;
	private boolean service;

	public void setClientProperties(String clientProperties) {
		this.clientProperties = clientProperties;
		logger.debug(new FedExLogEntry("...Set clientProperties to " + clientProperties + "..."));
	}

	public void setSecurityProperties(String securityProperties) {
		this.securityProperties = securityProperties;
		logger.debug(new FedExLogEntry("...Set securityProperties to " + securityProperties + "..."));
	}

	public void setClient(boolean client) {
		this.client = client;
		logger.debug(new FedExLogEntry("...Set client = " + client + "..."));
	}

	public void setService(boolean service) {
		this.service = service;
		logger.debug(new FedExLogEntry("...Set service = " + service + "..."));
	}

	public CSSBootstrap15() {
	}

	public CSSBootstrap15(boolean isClient, boolean isService, String clientProperties, String securityProperties, String rulesFile, String rolesFile) {
		try {
			logger.debug(new FedExLogEntry("...Initializing CSS Bootstrap..."));
			if (isClient) {
				logger.debug(new FedExLogEntry("...Configuring Client Functionality..."));
				clientConfig(clientProperties, securityProperties);
			}
			if (isService) {
				logger.debug(new FedExLogEntry("...Configuring Service Functionality..."));
				fileServiceConfig(securityProperties, rulesFile, rolesFile);
			}
			logger.always(new FedExLogEntry("...CSS Bootstrap Completed..."));
		}
		catch (Exception e) {
			logger.fatal(new FedExLogEntry("!!!!!!!!!Error Starting Bootstrap!!!!!!!!!  "));
			e.printStackTrace();
			throw new RuntimeException("!!Error Starting Common Security Service Bootstrap!!", e);
		}
	}

	@PostConstruct
	public void buildPolicy() {
		if ((this.service) && (!this.client)) {
			logger.error("If the service is set to true, then the client must also be true. The client is required to download the ESC policy from CDS. The client is required to be true for automatic certificate rotation.");
			throw new RuntimeException("If the service is set to true, then the client must also be true. The client is required to download the ESC policy from CDS. The client is required to be true for automatic certificate rotation.");
		}
		try {
			logger.debug(new FedExLogEntry("...Initializing CSS Bootstrap in buildPolicy..."));
			if (this.client) {
				logger.debug(new FedExLogEntry("...Configuring Client Functionality..."));
				clientConfig(this.clientProperties, this.securityProperties);
			}
			if (this.service) {
				logger.debug(new FedExLogEntry("...Configuring Service Functionality..."));
				serviceConfig(this.securityProperties);
			}
			logger.always(new FedExLogEntry("...CSS Bootstrap Completed..."));
		}
		catch (Exception e) {
			logger.fatal(new FedExLogEntry("!!!!!!!!!Error Starting Bootstrap!!!!!!!!!  "));
			e.printStackTrace();
			throw new RuntimeException("!!Error Starting Security API Bootstrap!!", e);
		}
	}

	@PreDestroy
	public void cancelTimerTasks() {
		PkcTokenGeneratorImpl.cancelExpirationTimer();
		PkcTokenGeneratorImpl.cancelRotationTimer();
		KeystoreCipherProviderImpl.cancelRotationTimer();
		RulesCacheEnterpriseImpl.cancelpolicyRefreshTimer();
		GroupsCacheGroupMajorListImpl.cancelTimerTask();
		LdapCipherProviderImpl.cancelTimerTask();
		RestrictionCacheImpl.cancelRestrctionRefreshTimer();
	}

	public void defaultClientConfig() {
		ClientCipherProviderFactory.configure(KeystoreCipherProviderImpl.getInstance());
		TokenGenerator gen = PkcTokenGeneratorImpl.getInstance();
		gen.configure();
	}

	public final void clientConfig(String clientProperties, String securityProperties) {
		ClientCipherProviderFactory.configure(KeystoreCipherProviderImpl.getInstance(securityProperties));
		String clientPath = "";
		String keyStorePath = "";
		try {
			Properties clientprops = FileLoader.getFileAsProperties(clientProperties);
			Properties securityprops = FileLoader.getFileAsProperties(securityProperties);
			SecurityUtils.trimProperties(clientprops);
			if ((clientProperties != null) && (clientProperties.equalsIgnoreCase("client.properties"))) {
				File testPath = new ClassPathResource(clientProperties).getFile();
				if (testPath != null) {
					clientPath = new ClassPathResource(clientProperties).getFile().getAbsolutePath();
					String keystoreFileNm = clientprops.getProperty("client.keystore.file");
					if ((keystoreFileNm != null) && (keystoreFileNm.length() > 0)) {
						File keystoreFile = FileLoader.getFile(keystoreFileNm);
						keyStorePath = keystoreFile.getAbsolutePath();
					}
					else {
						throw new Exception("client.keystore.file is not defined in client properties.");
					}
				}
			}
			else {
				if (clientProperties != null) {
					clientPath = new File(clientProperties).getAbsolutePath();
					KeystoreCipherProviderImpl.getInstance();
					File keyStoreFile = new File(clientprops.getProperty("client.keystore.file"));
					keyStorePath = keyStoreFile.getAbsolutePath();
				}
				else {
					logger.info(new FedExLogEntry("Invalid client properties path."));
				}
			}
			KeystoreCipherProviderImpl.setAbsolutePathOfClientFile(clientPath);
			KeystoreCipherProviderImpl.setAbsolutePathOfCert(keyStorePath);
			logger.info(new FedExLogEntry("client.properties path " + clientPath));
			logger.info(new FedExLogEntry("keystore  path " + keyStorePath));
			if ((FedExAppFrameworkProperties.getInstance().isManagedEnvironment()) || (!"false".equalsIgnoreCase(securityprops.getProperty("autocertrotation.flag")))) {
				PkcTokenAuthenticatorImpl.getInstance(securityProperties);
				LdapCipherProviderImpl.getInstance(securityProperties);
			}
		}
		catch (FileNotFoundException fe) {
			KeystoreCipherProviderImpl.setAbsolutePathOfClientFile("");
			KeystoreCipherProviderImpl.setAbsolutePathOfCert("");
			logger.info(new FedExLogEntry(fe.getMessage()));
		}
		catch (Exception e) {
			KeystoreCipherProviderImpl.setAbsolutePathOfClientFile("");
			KeystoreCipherProviderImpl.setAbsolutePathOfCert("");
			logger.info(new FedExLogEntry("Exception retrieving the file paths " + e.getMessage()));
		}
		TokenGenerator gen = PkcTokenGeneratorImpl.getInstance(securityProperties);
		gen.configure(clientProperties);
	}

	public void defaultServiceConfig() {
		ServerCipherProviderFactory.configure(LdapCipherProviderImpl.getInstance());
		RevocationProviderFactory.configure(LdapCipherProviderImpl.getInstance());
		RulesCacheEnterpriseImpl rulesCache = RulesCacheEnterpriseImpl.getInstance();
		RulesCacheFactory.setRulesCache(rulesCache);
		RolesCacheEnterpriseImpl rolesCache = RolesCacheEnterpriseImpl.getInstance();
		RolesCacheFactory.setRolesCache(rolesCache);
		RestrictionCache restrictionCache = RestrictionCacheImpl.getInstance();
		RestrictionCacheFactory.setRestrictionCache(restrictionCache);
		GroupsCacheGroupMajorListImpl groupsCache = GroupsCacheGroupMajorListImpl.getInstance();
		groupsCache.cache(RolesCacheFactory.getRolesCache().getRoles());
		GroupsCacheFactory.setGroupsCache(groupsCache);
		AuthorizorFactory.setAuthorizor(new AuthorizorEnterpriseImpl());
	}

	public void defaultFileServiceConfig() {
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
		RulesCacheEnterpriseImpl rulesCache = RulesCacheEnterpriseImpl.getInstance(securityProperties);
		RulesCacheFactory.setRulesCache(rulesCache);
		RolesCacheEnterpriseImpl rolesCache = RolesCacheEnterpriseImpl.getInstance(securityProperties);
		RolesCacheFactory.setRolesCache(rolesCache);
		RestrictionCache restrictionCache = RestrictionCacheImpl.getInstance(securityProperties);
		RestrictionCacheFactory.setRestrictionCache(restrictionCache);
		GroupsCacheGroupMajorListImpl groupsCache = GroupsCacheGroupMajorListImpl.getInstance(securityProperties);
		groupsCache.cache(RolesCacheFactory.getRolesCache().getRoles());
		GroupsCacheFactory.setGroupsCache(groupsCache);
		AuthorizorFactory.setAuthorizor(new AuthorizorEnterpriseImpl());
	}

	public final void fileServiceConfig(String securityProperties, String rulesFile, String rolesFile) {
		ServerCipherProviderFactory.configure(LdapCipherProviderImpl.getInstance(securityProperties));
		RevocationProviderFactory.configure(LdapCipherProviderImpl.getInstance(securityProperties));
		PkcTokenAuthenticatorImpl.getInstance(securityProperties);
		RulesCacheFileImpl rulesCache = RulesCacheFileImpl.getInstance();
		rulesCache.configure(rulesFile);
		RulesCacheFactory.setRulesCache(rulesCache);
		RolesCacheFileImpl rolesCache = RolesCacheFileImpl.getInstance();
		rolesCache.configure(rolesFile);
		RolesCacheFactory.setRolesCache(rolesCache);
		GroupsCacheGroupMajorListImpl groupsCache = GroupsCacheGroupMajorListImpl.getInstance(securityProperties);
		groupsCache.cache(RolesCacheFactory.getRolesCache().getRoles());
		GroupsCacheFactory.setGroupsCache(groupsCache);
		AuthorizorFactory.setAuthorizor(new AuthorizorImpl());
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\bootstrap\CSSBootstrap15.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */