package com.fedex.security.server;

import com.fedex.enterprise.security.api.SecurityService;
import com.fedex.enterprise.security.api.SecurityServiceImpl;
import com.fedex.enterprise.security.rule.RuleData;
import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import com.fedex.framework.utility.FedExAppFrameworkProperties;
import com.fedex.security.common.FileLoader;
import com.fedex.security.common.LRUCache;
import com.fedex.security.exceptions.SecurityConfigurationException;

import javax.xml.parsers.FactoryConfigurationError;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;

public class RulesCacheEnterpriseImpl
		implements RulesCache {
	private static final String DISK_CACHE_FILE = "RulesCacheEnterpriseImpl.cache";
	private static final String POLICY_REFRESH_IN_SECONDS_PROP = "security.api.service.policy.refresh";
	private static final String LOCAL_CACHE_DIR = "security.api.local.cache.dir";
	private static final String DENY = "N";
	private static final String GRANT = "Y";
	private static final FileLoader localLoader = new FileLoader();
	private Map<String, List<Rule>> policyCache;
	private List<Long> roleDocIds;
	private LRUCache<Permission, List<Rule>> ruleMatchCache;
	private long policyRefreshInSeconds;
	private String localCacheDir;
	private static Timer policyRefreshTimer;
	private long policyTimerSerial;
	private static String idmUrl;
	private boolean queryIDM = false;
	private boolean queryRestriction = false;
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(RulesCacheEnterpriseImpl.class.getName());

	public List<Long> getRoleDocIds() {
		return this.roleDocIds;
	}

	private RulesCacheEnterpriseImpl() {
		this("security.properties");
	}

	private RulesCacheEnterpriseImpl(String pathWithPropsFileName) {
		Properties props = FileLoader.getFileAsProperties(pathWithPropsFileName);
		if ((!props.containsKey("security.api.service.policy.refresh")) || (!props.containsKey("security.api.local.cache.dir"))) {
			String msg = "Failed to configure enterprise rules cache due to missing values provided for properties, exiting. Missing property value in security.properties file.";
			logger.fatal(new FedExLogEntry("Failed to configure enterprise rules cache due to missing values provided for properties, exiting. Missing property value in security.properties file."));
			throw new RuntimeException("Failed to configure enterprise rules cache due to missing values provided for properties, exiting. Missing property value in security.properties file.");
		}
		try {
			this.policyRefreshInSeconds = Long.parseLong(props.getProperty("security.api.service.policy.refresh"));
			this.localCacheDir = props.getProperty("security.api.local.cache.dir");
			if (props.containsKey("idm.url")) {
				idmUrl = props.getProperty("idm.url");
				this.queryIDM = true;
				IDM.idmCheck = true;
				logger.debug("IDM delegation honor is enabled (url found in security.properties)");
			}
			else {
				logger.debug("IDM delegation honor is disabled (no url found in security.properties)");
			}
			new File(this.localCacheDir).mkdirs();
		}
		catch (Exception e) {
			String msg = "Failed to configure enterprise rules cache  due to missing values provided for properties, exiting. Invalid property value in security.properties file.  Directory name: " + this.localCacheDir;
			logger.fatal(new FedExLogEntry(msg), e);
			throw new RuntimeException(msg, e);
		}
		this.policyCache = new ConcurrentHashMap();
		load();
		manageTimers();
		logger.info(new FedExLogEntry("Enterprise Rules Cache Initialized"));
	}

	private static final class RulesCacheEnterpriseImplHolder {
		private static RulesCacheEnterpriseImpl instance = null;

		public static RulesCacheEnterpriseImpl getInstance() {
			if (instance == null) {
				instance = new RulesCacheEnterpriseImpl(null);
			}
			return instance;
		}

		public static RulesCacheEnterpriseImpl getInstance(String propsFile) {
			if (instance == null) {
				instance = new RulesCacheEnterpriseImpl(propsFile);
			}
			return instance;
		}
	}

	public static final RulesCacheEnterpriseImpl getInstance() {
		logger.trace(new FedExLogEntry("RulesCacheEnterpriseImpl instance returned"));
		return RulesCacheEnterpriseImplHolder.getInstance();
	}

	public static final RulesCacheEnterpriseImpl getInstance(String propsFile) {
		logger.trace(new FedExLogEntry("RulesCacheEnterpriseImpl instance w/ props file returned"));
		return RulesCacheEnterpriseImplHolder.getInstance(propsFile);
	}

	public void enableRuleMatchCache(int maxSize) {
		if (!isRuleMatchCacheEnabled()) {
			this.ruleMatchCache = new LRUCache(maxSize);
		}
		else {
			logger.warn(new FedExLogEntry("Rule match cache is already enabled, ignoring"));
		}
	}

	public boolean isRuleMatchCacheEnabled() {
		return this.ruleMatchCache != null;
	}

	public List<Rule> getDenyRules(String resource, String action, Map<?, ?> context) {
		List<Rule> rules = null;
		List<Rule> denyRules = null;
		Permission requestedPermission = new Permission(resource, action);
		if (isRuleMatchCacheEnabled()) {
			List<Rule> cachedRules = this.ruleMatchCache.get(requestedPermission);
			if (cachedRules != null) {
				rules = cachedRules;
			}
		}
		if (rules == null) {
			if ((resource != null) && (action != null)) {
				if ((resource.contains("*")) || (action.contains("*"))) {
					logger.warn(new FedExLogEntry("Wild cards are not accepted by isAllowed. resource:" + resource + " action:" + action));
					throw new RuntimeException("Wild cards are not accepted by isAllowed.");
				}
				denyRules = this.policyCache.get("N");
				if ((denyRules != null) && (denyRules.size() > 0)) {
					for (Rule rule : denyRules) {
						if (rule.matches(resource, action, context)) {
							if (rules == null) {
								rules = new ArrayList();
							}
							rules.add(rule);
							logger.debug(new FedExLogEntry("DENY Matched Rule: " + rule));
						}
					}
				}
			}
			if (isRuleMatchCacheEnabled()) {
				this.ruleMatchCache.put(requestedPermission, rules == null ? new ArrayList(0) : rules);
			}
		}
		return rules;
	}

	public List<Rule> getGrantRules(String resource, String action, Map<?, ?> context) {
		List<Rule> rules = null;
		List<Rule> grantRules = null;
		Permission requestedPermission = new Permission(resource, action);
		if (isRuleMatchCacheEnabled()) {
			List<Rule> cachedRules = this.ruleMatchCache.get(requestedPermission);
			if (cachedRules != null) {
				rules = cachedRules;
			}
		}
		if (rules == null) {
			if ((resource != null) && (action != null)) {
				if ((resource.contains("*")) || (action.contains("*"))) {
					logger.warn(new FedExLogEntry("Wild cards are not accepted by isAllowed. resource:" + resource + " action:" + action));
					throw new RuntimeException("Wild cards are not accepted by isAllowed.");
				}
				grantRules = this.policyCache.get("Y");
				if ((grantRules != null) && (grantRules.size() > 0)) {
					for (Rule rule : grantRules) {
						if (rule.matches(resource, action, context)) {
							if (rules == null) {
								rules = new ArrayList();
							}
							rules.add(rule);
							logger.debug(new FedExLogEntry("GRANT Matched Rule: " + rule));
						}
					}
				}
			}
			if (isRuleMatchCacheEnabled()) {
				this.ruleMatchCache.put(requestedPermission, rules == null ? new ArrayList(0) : rules);
			}
		}
		return rules;
	}

	private synchronized void load() {
		SecurityService secService = new SecurityServiceImpl();
		List<RuleData> rules = null;
		List<Rule> tempGrantCache = new ArrayList();
		List<Rule> tempDenyCache = new ArrayList();
		IDM myIDM = new IDM(idmUrl, this.localCacheDir);
		String appId = getClientIdFromFingerPrint();
		logger.debug(new FedExLogEntry("[Load Rules]App Id = " + appId));
		String message;
		try {
			rules = secService.getRulesForApplicationAPI(appId);
		}
		catch (RuntimeException rte) {
			message = rte.getMessage();
			if ((message != null) &&
			    (message.startsWith("Old thread"))) {
				logger.warn(new FedExLogEntry(message + " cancelling timer."));
				cancelpolicyRefreshTimer();
			}
		}
		catch (Exception e) {
			message = e.getMessage();
		}
		if (rules != null) {
			logger.debug(new FedExLogEntry("[Load Rules]Total number of rules in the policy: " + rules.size()));
		}
		this.roleDocIds = new ArrayList();
		if ((rules == null) || (rules.isEmpty())) {
			logger.warn(new FedExLogEntry("[Load Rules]Failed to retrieve policy from CDS, attempting to fall back to LKG..."));
			Object fromDisk = localLoader.readObjectFromDisk(this.localCacheDir + File.separator + "RulesCacheEnterpriseImpl.cache");
			if ((fromDisk != null) && ((fromDisk instanceof Map))) {
				try {
					Map<String, List<Rule>> policyCacheFromDisk = (Map)fromDisk;
					if ((policyCacheFromDisk != null) && (!policyCacheFromDisk.isEmpty())) {
						this.policyCache.putAll(policyCacheFromDisk);
						logger.warn(new FedExLogEntry("[Load Rules]Successfully loaded policy LKG from disk."));
					}
				}
				catch (Exception e) {
					logger.error(new FedExLogEntry("[Load Rules]Error loading policy from CDS and unable to load LKG cache from disk!"), e);
				}
			}
			fromDisk = null;
		}
		else {
			for (RuleData rule : rules) {
				logger.debug(new FedExLogEntry("Rule: " + rule));
				CustomAuthorizor custAuthZ = null;
				String className = rule.getCustAuthZClassNm();
				if ((className != null) && (!className.trim().isEmpty())) {
					try {
						Class<?> c = Class.forName(className);
						custAuthZ = (CustomAuthorizor)c.newInstance();
					}
					catch (Exception e) {
						logger.warn(new FedExLogEntry("Bad Rule: could not find or create custom authorizor (" + className + " for Rule #" + rule.getDocId()));
						custAuthZ = null;
					}
				}
				if (!this.roleDocIds.contains(Long.valueOf(rule.getRoleDocId()))) {
					logger.debug(new FedExLogEntry("Adding Role Id: " + rule.getRoleDocId()));
					this.roleDocIds.add(Long.valueOf(rule.getRoleDocId()));
				}
				else {
					logger.debug(new FedExLogEntry("Role Id: " + rule.getRoleDocId() + " already exists, don't need a duplicate..."));
				}
				if (rule.getGrantFlg() == 'Y') {
					Rule tempRule = new Rule(rule.getRoleNm(), rule.getResourceNm(), rule.getActionNm(), rule.getGrantFlg(), rule.getExtendedRuleList(), custAuthZ);
					tempGrantCache.add(tempRule);
					logger.debug(new FedExLogEntry("Added the following Rule to the GRANT cache: " + tempRule));
				}
				else {
					if (rule.getGrantFlg() == 'N') {
						Rule tempRule = new Rule(rule.getRoleNm(), rule.getResourceNm(), rule.getActionNm(), rule.getGrantFlg(), rule.getExtendedRuleList(), custAuthZ);
						tempDenyCache.add(tempRule);
						logger.debug(new FedExLogEntry("Added the following Rule to the DENY cache: " + tempRule));
					}
					else {
						logger.warn(new FedExLogEntry("[Load Rule]Problem with a rule, neither GRANT nor DENY is set, unable to use Rule #" + rule.getDocId()));
					}
				}
			}
			this.policyCache.put("Y", tempGrantCache);
			this.policyCache.put("N", tempDenyCache);
			try {
				localLoader.saveObjectToDisk(this.localCacheDir + File.separator + "RulesCacheEnterpriseImpl.cache", this.policyCache);
				logger.debug(new FedExLogEntry("[RulesCache]LKG is written to disk at location: RulesCacheEnterpriseImpl.cache"));
			}
			catch (Exception e) {
				logger.always(new FedExLogEntry("[RulesCache]Error attempting to write LKG for policy to disk: " + this.localCacheDir + File.separator + "RulesCacheEnterpriseImpl.cache"), e);
			}
		}
		if (this.queryIDM) {
			try {
				myIDM.queryIDMWebService();
				logger.debug("myIDM.queryIDMWebService() called");
			}
			catch (Exception exc) {
				logger.warn("myIDM.queryIDMWebService() threw exception" + exc.toString());
			}
		}
	}

	public List<Rule> getRules(String resource, String action) {
		return null;
	}

	private class PolicyRefreshCacheTask
			extends TimerTask {
		private PolicyRefreshCacheTask() {
		}

		public void run() {
			RulesCacheEnterpriseImpl.logger.trace(new FedExLogEntry("PolicyRefreshCacheTask timer running."));
			try {
				RulesCacheEnterpriseImpl.this.load();
				RolesCacheFactory.getRolesCache().triggerUpdate();
				RulesCacheEnterpriseImpl.logger.warn(new FedExLogEntry("Completed Security API Policy refresh."));
			}
			catch (RuntimeException rte) {
				String message = rte.getMessage();
				if ((message != null) &&
				    (message.startsWith("Old thread"))) {
					RulesCacheEnterpriseImpl.logger.warn(new FedExLogEntry(message));
					cancel();
				}
			}
			catch (FactoryConfigurationError fce) {
				RulesCacheEnterpriseImpl.logger.warn(new FedExLogEntry("Security policy was not refreshed successfully. It appears that the Security API was hot deployed during the refresh attempt. This thread should be terminated."));
				cancel();
			}
			catch (Exception e) {
				String message = e.getMessage();
				if (message != null) {
					if (message.startsWith("Old thread")) {
						RulesCacheEnterpriseImpl.logger.warn(new FedExLogEntry(message));
						cancel();
					}
					else {
						RulesCacheEnterpriseImpl.logger.error(new FedExLogEntry("Exception attempting to load the policy from the center datastore, will try again later."));
					}
				}
				else {
					RulesCacheEnterpriseImpl.logger.error(new FedExLogEntry(" An exception was thrown while attempting to retrieve the policy from CDS. Exception contained a null message!"));
				}
			}
		}
	}

	private void manageTimers() {
		if (this.policyTimerSerial < System.currentTimeMillis() - 2L * this.policyRefreshInSeconds * 1000L) {
			if (policyRefreshTimer != null) {
				policyRefreshTimer.cancel();
				policyRefreshTimer = null;
			}
			policyRefreshTimer = new Timer(true);
			policyRefreshTimer.schedule(new PolicyRefreshCacheTask(), this.policyRefreshInSeconds * 1000L, this.policyRefreshInSeconds * 1000L);
			this.policyTimerSerial = System.currentTimeMillis();
			logger.info(new FedExLogEntry("Policy cache timer (re)started"));
		}
		else {
			logger.trace(new FedExLogEntry("Policy cache timer status OK"));
		}
	}

	private static final String getClientIdFromFingerPrint() {
		String clientId = FedExAppFrameworkProperties.getInstance().getAppId();
		if ((clientId == null) || (clientId.trim().equals(""))) {
			clientId = "BAD";
		}
		if (clientId.matches("^APP[0-9]*[1-9][0-9]*$")) {
			return clientId.substring(3);
		}
		if (clientId.matches("^[0-9]*[1-9][0-9]*$")) {
			return clientId;
		}
		logger.fatal(new FedExLogEntry("Application ID is missing or invalid. Verify location and appID contents in fp.properties file. Can not retrieve security policy."));
		throw new SecurityConfigurationException("Unable to determine application id (check app.id), unable to retrieve security policy!");
	}

	public static void cancelpolicyRefreshTimer() {
		if (policyRefreshTimer != null) {
			policyRefreshTimer.cancel();
		}
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\server\RulesCacheEnterpriseImpl.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */