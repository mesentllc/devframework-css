package com.fedex.security.server;

import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import com.fedex.security.common.FileLoader;
import com.fedex.security.common.LRUCache;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public class RulesCacheFileImpl
		implements RulesCache {
	private static final String DEFAULT_FILE = "authorization.rules";
	private List<Rule> cache;
	private LRUCache<Permission, List<Rule>> ruleMatchCache;
	private String rulesFileName;
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(RulesCacheFileImpl.class.getName());

	private RulesCacheFileImpl() {
		this.cache = new ArrayList();
		logger.info(new FedExLogEntry("Rules cache initialized"));
	}

	private static final class RulesCacheFileImplHolder {
		private static final RulesCacheFileImpl instance = new RulesCacheFileImpl();
	}

	public static final RulesCacheFileImpl getInstance() {
		return RulesCacheFileImplHolder.instance;
	}

	public final synchronized void configure() {
		configure(null);
	}

	public final synchronized void configure(String rulesFileName) {
		if (this.cache.size() == 0) {
			if (rulesFileName != null) {
				this.rulesFileName = rulesFileName;
				logger.info(new FedExLogEntry("Using Rules File:" + this.rulesFileName));
			}
			else {
				this.rulesFileName = "authorization.rules";
				logger.info(new FedExLogEntry("rulesFileName is null, using filename of " + this.rulesFileName));
			}
			load();
		}
		else {
			logger.info(new FedExLogEntry("Rules have already been loaded.  Rules can only be loaded once, ignoring"));
		}
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

	public List<Rule> getRules(String resource, String action) {
		List<Rule> rules = null;
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
				if (this.cache.size() > 0) {
					for (Rule rule : this.cache) {
						if (rule.matches(resource, action, null)) {
							if (rules == null) {
								rules = new ArrayList();
							}
							rules.add(rule);
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
		if (this.rulesFileName != null) {
			InputStream is = null;
			BufferedReader in = null;
			try {
				is = FileLoader.getFileAsInputStream(this.rulesFileName);
				logger.trace(new FedExLogEntry("Loaded " + this.rulesFileName));
				if (is == null) {
					logger.fatal(new FedExLogEntry("Unable to locate rules file: " + this.rulesFileName));
					throw new RuntimeException("Unable to locate rules file.");
				}
				Pattern whiteList = Pattern.compile("([a-zA-Z0-9_-]+|[*]);(([a-zA-Z0-9_-]([a-zA-Z0-9_-]+[/])*;)|(([a-zA-Z0-9_-]+[/])*([a-zA-Z0-9_-])+;)|([a-zA-Z0-9_-]+/)+[*];|[*];)(([a-zA-Z0-9_-]+|[*]))(;([^;*])+)*");
				in = new BufferedReader(new InputStreamReader(is));
				String temp = null;
				while ((temp = in.readLine()) != null) {
					temp = temp.trim();
					logger.trace(new FedExLogEntry("Processing line: " + temp));
					if ((!temp.startsWith("#")) && (!"".equals(temp.trim()))) {
						logger.trace(new FedExLogEntry("Time to start the regex for this line."));
						if (whiteList.matcher(temp).matches()) {
							logger.trace(new FedExLogEntry("Regex passed for this line."));
							String[] rawRule = temp.split(";");
							CustomAuthorizor authorizor = null;
							if ((rawRule.length > 3) && (rawRule[3] != null)) {
								try {
									Class c = Class.forName(rawRule[3]);
									authorizor = (CustomAuthorizor)c.newInstance();
								}
								catch (Exception e) {
									logger.error(new FedExLogEntry("bad rule: could not find or create custom authorizor " + temp));
									throw new RuntimeException("Unable to parse rules file.", e);
								}
							}
							this.cache.add(new Rule(rawRule[0], rawRule[1], rawRule[2], authorizor));
							logger.trace(new FedExLogEntry("New rule added to the cache for this line."));
						}
						else {
							logger.error(new FedExLogEntry("bad rule: " + temp));
							throw new RuntimeException("Unable to parse rules file.");
						}
					}
				}
				in.close();
				is.close();
				try {
					if (in != null) {
						in.close();
					}
				}
				catch (IOException ioe) {
					logger.warn(new FedExLogEntry(ioe.getStackTrace().toString()));
				}
				try {
					if (is != null) {
						is.close();
					}
				}
				catch (IOException ioe) {
					logger.warn(new FedExLogEntry(ioe.getStackTrace().toString()));
				}
				logger.trace(new FedExLogEntry("Rules:" + this.cache));
			}
			catch (IOException e) {
				logger.fatal(new FedExLogEntry("unable to load rules file: " + this.rulesFileName + " " + e.getMessage()));
				throw new RuntimeException("Unable to load rules file.");
			}
			finally {
				try {
					if (in != null) {
						in.close();
					}
				}
				catch (IOException ioe) {
					logger.warn(new FedExLogEntry(ioe.getStackTrace().toString()));
				}
				try {
					if (is != null) {
						is.close();
					}
				}
				catch (IOException ioe) {
					logger.warn(new FedExLogEntry(ioe.getStackTrace().toString()));
				}
			}
		}
	}

	public List<Long> getRoleDocIds() {
		return null;
	}

	public List<Rule> getDenyRules(String resource, String action, Map<?, ?> context) {
		return null;
	}

	public List<Rule> getGrantRules(String resource, String action, Map<?, ?> context) {
		return null;
	}
}
