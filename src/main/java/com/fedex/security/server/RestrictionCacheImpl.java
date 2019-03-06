package com.fedex.security.server;

import com.fedex.enterprise.security.api.SecurityServiceImpl;
import com.fedex.enterprise.security.role.restriction.RestrictionData;
import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import com.fedex.framework.utility.FedExAppFrameworkProperties;
import com.fedex.security.common.FileLoader;
import com.fedex.security.common.StringUtils;
import com.fedex.security.exceptions.SecurityConfigurationException;

import javax.xml.parsers.FactoryConfigurationError;
import java.io.File;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;

public class RestrictionCacheImpl
		implements RestrictionCache {
	private static String cacheFileName = "RestrictionCache.cache";
	public static final String DOMAIN_DATA_REFRESH_IN_SECONDS_PROP = "security.api.domain.data.cache";
	public static final String LOCAL_CACHE_DIR = "security.api.local.cache.dir";
	private static long domainDataRefreshInSeconds;
	public static final String DOMAIN_DATA_CHECK = "domain.data.check.enable";
	private static List<RestrictionData> restrictionList;
	private String localCacheDir = "";
	public Map<String, RestrictionData> cache;
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(RestrictionCacheImpl.class.getName());
	public static final FileLoader localLoader = new FileLoader();
	private static Timer restrictionRefreshTimer;
	private static long restrictionTimerSerial = 0L;

	protected RestrictionCacheImpl(String pathWithPropsFileName) {
		Properties props = FileLoader.getFileAsProperties(pathWithPropsFileName);
		if ((props != null) && (props.containsKey("domain.data.check.enable")) && ("true".equalsIgnoreCase(props.getProperty("domain.data.check.enable")))) {
			if (props.getProperty("security.api.domain.data.cache") != null) {
				domainDataRefreshInSeconds = Long.parseLong(props.getProperty("security.api.domain.data.cache"));
			}
			else {
				domainDataRefreshInSeconds = 86400L;
				logger.always(new FedExLogEntry("Domain data check is enable but security.api.domain.data.cache is not set so defaulting to 24 hrs"));
			}
			this.localCacheDir = props.getProperty("security.api.local.cache.dir");
			if (props.getProperty("security.api.local.cache.dir") != null) {
				logger.always(new FedExLogEntry("local Cahe directorysecurity.api.local.cache.dir"));
			}
			this.cache = new ConcurrentHashMap();
			load();
			manageTimers();
			logger.warn("Domain data check is enabled");
		}
		else {
			logger.warn("Domain data check is not enabled)");
		}
	}

	protected RestrictionCacheImpl() {
		this("security.properties");
	}

	private static final class RestrictionCacheImplHolder {
		private static RestrictionCacheImpl instance = null;

		public static RestrictionCacheImpl getInstance() {
			if (instance == null) {
				instance = new RestrictionCacheImpl();
			}
			return instance;
		}

		public static RestrictionCacheImpl getInstance(String propsFile) {
			if (instance == null) {
				instance = new RestrictionCacheImpl(propsFile);
			}
			return instance;
		}
	}

	public static final RestrictionCacheImpl getInstance() {
		logger.trace(new FedExLogEntry("RestrictionCacheImpl instance returned"));
		return RestrictionCacheImplHolder.getInstance();
	}

	public static final RestrictionCacheImpl getInstance(String propsFile) {
		logger.trace(new FedExLogEntry("RestrictionCacheImpl instance w/ props file returned"));
		return RestrictionCacheImplHolder.getInstance(propsFile);
	}

	public void writeRestrictionCacheToDisk(Map<String, RestrictionData> restrictionList) {
		try {
			logger.info(new FedExLogEntry("Writing Restriction cache to disk : " + restrictionList.size()));
			this.cache.putAll(restrictionList);
			localLoader.saveObjectToDisk(this.localCacheDir + File.separator + cacheFileName, this.cache);
			logger.info(new FedExLogEntry("Restriction cache written to disk at location: " + cacheFileName));
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("[RestrictionCache] attempting to write Restriction cache to disk: " + e));
		}
	}

	public synchronized void load() {
		SecurityServiceImpl secService = new SecurityServiceImpl();
		List<RestrictionData> restrictions = null;
		String appId = FedExAppFrameworkProperties.getInstance().getAppId();
		logger.always(new FedExLogEntry("[Load Restrictions]App Id = " + appId));
		try {
			restrictions = secService.getRestrictionsOnRoles(appId);
		}
		catch (RuntimeException rte) {
			String message = rte.getMessage();
			restrictions = null;
			if (message != null) {
				if (message.startsWith("Old thread")) {
					logger.warn(new FedExLogEntry(message + " cancelling timer."), rte);
					cancelRestrctionRefreshTimer();
				}
				else {
					logger.warn(new FedExLogEntry("Runtime Exception occured while retrieving restriction from CDS " + message), rte);
				}
			}
		}
		catch (Exception e) {
			restrictions = null;
			logger.always(new FedExLogEntry("Exception caused by " + e.getCause() + " Message : " + e.getMessage()), e);
		}
		if (restrictions == null) {
			logger.always(new FedExLogEntry("[Load Rules]Failed to retrieve restrictions from CDS, attempting to fall back to LKG..."));
			Object fromDisk = localLoader.readObjectFromDisk(this.localCacheDir + File.separator + cacheFileName);
			if ((fromDisk != null) && ((fromDisk instanceof Map))) {
				try {
					Map<String, RestrictionData> restrictionCacheFromDisk = (Map)fromDisk;
					if ((restrictionCacheFromDisk != null) && (!restrictionCacheFromDisk.isEmpty())) {
						Map<String, RestrictionData> newCache = new HashMap(restrictionCacheFromDisk.size());
						newCache.putAll(restrictionCacheFromDisk);
						this.cache = newCache;
						logger.always(new FedExLogEntry("[Load Restrictions]Successfully loaded restrction LKG from disk."));
					}
				}
				catch (Exception e) {
					logger.error(new FedExLogEntry("[Load Restrictions]Error loading restriction from CDS and unable to load LKG cache from disk!"), e);
				}
			}
			else {
				logger.always(new FedExLogEntry("[Load Restrictions]Unable to load restriction LKG from disk."));
			}
			fromDisk = null;
		}
		else {
			logger.debug(new FedExLogEntry("[Load Restrictions]Total number of restrictions returned from CDS: " + restrictions.size()));
			Map<String, RestrictionData> newCache = new HashMap(restrictions.size());
			for (RestrictionData restrictionData : restrictions) {
				logger.trace(new FedExLogEntry("Adding Restriction " + restrictionData.getRoleNm() + ": " + restrictionData.toString()));
				if (!StringUtils.isNullOrBlank(restrictionData.getEmplId())) {
					newCache.put(restrictionData.getEmplId() + ":" + restrictionData.getRoleNm(), restrictionData);
				}
				else {
					newCache.put(restrictionData.getGroupNm() + ":" + restrictionData.getRoleNm(), restrictionData);
				}
			}
			this.cache = newCache;
			try {
				localLoader.saveObjectToDisk(this.localCacheDir + File.separator + cacheFileName, this.cache);
			}
			catch (Exception e) {
				logger.always(new FedExLogEntry("Exception while saving the object " + e.getMessage()), e);
			}
		}
	}

	public Map<String, RestrictionData> getRestrictions() {
		if (this.cache != null) {
			return this.cache;
		}
		throw new SecurityConfigurationException("Restriction data was unable to be retrieved from CDS/LKG");
	}

	private void manageTimers() {
		if (restrictionTimerSerial < System.currentTimeMillis() - domainDataRefreshInSeconds * 1000L) {
			if (restrictionRefreshTimer != null) {
				restrictionRefreshTimer.cancel();
				restrictionRefreshTimer = null;
			}
			restrictionRefreshTimer = new Timer(true);
			restrictionRefreshTimer.schedule(new RestrictionRefreshCacheTask(), domainDataRefreshInSeconds * 1000L, domainDataRefreshInSeconds * 1000L);
			restrictionTimerSerial = System.currentTimeMillis();
			logger.info(new FedExLogEntry("Restriction cache timer (re)started"));
		}
		else {
			logger.trace(new FedExLogEntry("Restriction cache timer status OK"));
		}
	}

	private class RestrictionRefreshCacheTask
			extends TimerTask {
		private RestrictionRefreshCacheTask() {
		}

		public void run() {
			RestrictionCacheImpl.logger.trace(new FedExLogEntry("RestrictionRefreshCacheTask timer running."));
			try {
				Thread.currentThread().setName("RestrictionTimer-" + Thread.currentThread().getId() + new Date().toString().trim());
				RestrictionCacheImpl.this.load();
				RestrictionCacheImpl.logger.warn(new FedExLogEntry("Completed Security API Domain Data/Restrictions refresh."));
			}
			catch (RuntimeException rte) {
				String message = rte.getMessage();
				if ((message != null) &&
				    (message.startsWith("Old thread"))) {
					RestrictionCacheImpl.logger.warn(new FedExLogEntry(message));
					cancel();
				}
			}
			catch (FactoryConfigurationError fce) {
				RestrictionCacheImpl.logger.warn(new FedExLogEntry("Security policy was not refreshed successfully. It appears that the Security API was hot deployed during the refresh attempt. This thread should be terminated."));
				cancel();
			}
			catch (Exception e) {
				String message = e.getMessage();
				if (message != null) {
					if (message.startsWith("Old thread")) {
						RestrictionCacheImpl.logger.warn(new FedExLogEntry(message));
						cancel();
					}
					else {
						RestrictionCacheImpl.logger.error(new FedExLogEntry("Exception attempting to load the restrictions from the center datastore, will try again later."));
					}
				}
				else {
					RestrictionCacheImpl.logger.error(new FedExLogEntry(" An exception was thrown while attempting to retrieve the policy from CDS. Exception contained a null message!"));
				}
			}
		}
	}

	public static void cancelRestrctionRefreshTimer() {
		if (restrictionRefreshTimer != null) {
			restrictionRefreshTimer.cancel();
		}
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\server\RestrictionCacheImpl.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */