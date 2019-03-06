package com.fedex.security.client;

import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import com.fedex.framework.utility.FedExAppFrameworkProperties;
import com.fedex.security.common.CachedItem;
import com.fedex.security.common.FileLoader;
import com.fedex.security.common.StringUtils;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public final class KeystoreExpirationCheck {
	private static Map<String, Map<String, CachedItem>> keyStoreCache = Collections.synchronizedMap(new HashMap());
	private static Map<String, String> keyStoreState = new HashMap();
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(KeystoreExpirationCheck.class.getName());
	private static final String sFATAL = "FATL";
	private static final String sERROR = "ERR";
	private static final String sWARN = "WARN";
	private static final String sINFO = "INFO";
	private static final String EXPIRED = "EXPIRED";
	private static final String logLevel = "LOG_LEVEL";
	private static final String certState = "CERT_STATE";
	private static boolean cdsCertFlag = false;
	private static boolean configCheckonStartup = true;
	private static boolean forcePostRotationCheck = false;
	private static boolean demandRotation = false;
	private static String DEMANDSEMAPHORE = "rotateasap.tmp";
	private static File semaphoreFile;
	private static int CERTINFOTHRESHOLD = 40;
	private static int CERTWARNTHRESHOLD = 30;
	private static int CERTERRORTHRESHOLD = 14;
	private static int CERTFATALTHRESHOLD = 7;
	private static long CDSCERTQUERYINTERVAL = 86400000L;
	private static long FATALLOGINTERVAL = 43200000L;
	private static String CDSCERTQUERYSUFFIX = "_cds_cert_query_timestamp";
	private static String FATALLOGSUFFIX = "_fatal_logged_timestamp";
	public static final String CLIENT_KEYSTORE_TYPE = "client.keystore.type";
	public static final String CLIENT_KEYSTORE_FILE_PROP = "client.keystore.file";
	public static final String CLIENT_KEYSTORE_PASS_PROP = "client.keystore.password";
	public static final String CLIENT_KEYSTORE_KEY_ALIAS_PROP = "client.keystore.key.alias";
	public static final String CLIENT_PRIVATE_KEY_PASS_PROP = "client.private.key.password";
	private static final FedExLoggerInterface auditLogger = FedExLogger.getAuditLogger();
	public static final String service_name = "943415_cds";
	private static final String dateTimeFormatString = "yyyyMMddhh24mmss";
	private static String certRotationLckFile = "CertRotation.lck";

	public static void getCertState(Date certDate) {
		boolean statusFlg = false;
		Calendar workingCalendar = Calendar.getInstance();
		Date today = workingCalendar.getTime();
		workingCalendar.add(5, CERTINFOTHRESHOLD);
		Date infoThreshold = workingCalendar.getTime();
		workingCalendar = Calendar.getInstance();
		workingCalendar.add(5, CERTWARNTHRESHOLD);
		Date warningThreshold = workingCalendar.getTime();
		workingCalendar = Calendar.getInstance();
		workingCalendar.add(5, CERTERRORTHRESHOLD);
		Date errorThreshold = workingCalendar.getTime();
		workingCalendar = Calendar.getInstance();
		workingCalendar.add(5, CERTFATALTHRESHOLD);
		Date fatalThreshold = workingCalendar.getTime();
		if (certDate.before(today)) {
			keyStoreState.put("CERT_STATE", "EXPIRED");
			keyStoreState.put("LOG_LEVEL", "FATL");
			statusFlg = true;
		}
		if ((!statusFlg) && ((certDate.before(fatalThreshold)) || (certDate.equals(fatalThreshold)))) {
			keyStoreState.put("CERT_STATE", "FATL");
			keyStoreState.put("LOG_LEVEL", "FATL");
			statusFlg = true;
		}
		if ((!statusFlg) && (certDate.after(fatalThreshold)) && (certDate.before(errorThreshold))) {
			keyStoreState.put("CERT_STATE", "ERR");
			keyStoreState.put("LOG_LEVEL", "ERR");
			statusFlg = true;
		}
		if ((!statusFlg) && (certDate.after(errorThreshold)) && (certDate.before(warningThreshold))) {
			keyStoreState.put("CERT_STATE", "WARN");
			keyStoreState.put("LOG_LEVEL", "WARN");
			statusFlg = true;
		}
		if ((!statusFlg) && (certDate.after(warningThreshold)) && (certDate.before(infoThreshold))) {
			keyStoreState.put("CERT_STATE", "INFO");
			keyStoreState.put("LOG_LEVEL", "INFO");
			statusFlg = true;
		}
		if (certDate.after(infoThreshold)) {
			keyStoreState.put("CERT_STATE", "GOOD");
			keyStoreState.put("LOG_LEVEL", "INFO");
		}
	}

	private static boolean queryCDSForCert(Date cacheExprDate, String clientId) {
		boolean returnValue = false;
		try {
			Date cdsCertExpiredate = KeystoreRotation.getCDSCertExpirationDate();
			if (!configCheckonStartup) {
				updateCacheFlag(clientId, CDSCERTQUERYSUFFIX);
			}
			if (cdsCertExpiredate == null) {
				logger.info(new FedExLogEntry(" The Security API did not find a cert in CDS "));
				cdsCertFlag = true;
				forcePostRotationCheck = true;
			}
			else {
				if (cacheExprDate.before(cdsCertExpiredate)) {
					logger.info(new FedExLogEntry(" Found a CDS cert that is newer than the cached cert"));
					logger.info(new FedExLogEntry(" cdsCertExpiredate: " + cdsCertExpiredate + " cacheExprDate: " + cacheExprDate));
					returnValue = true;
				}
				else {
					if (cacheExprDate.equals(cdsCertExpiredate)) {
						logger.info(new FedExLogEntry(" Found CDS cert that has the same expiration date as the cached cert."));
						logger.info(new FedExLogEntry(" cdsCertExpiredate: " + cdsCertExpiredate + " cacheExprDate: " + cacheExprDate));
						forcePostRotationCheck = true;
					}
					else {
						if (cacheExprDate.after(cdsCertExpiredate)) {
							logger.info(new FedExLogEntry(" Found CDS cert that is older than the cached cert"));
							logger.info(new FedExLogEntry(" cdsCertExpiredate: " + cdsCertExpiredate + " cacheExprDate: " + cacheExprDate));
							forcePostRotationCheck = true;
						}
						else {
							logger.info(new FedExLogEntry("The Security API retrieved an invalid expiration date from CDS for the security cert. cdsCertExpiredate: " + cdsCertExpiredate + "cacheExprDate: " + cacheExprDate));
						}
					}
				}
			}
		}
		catch (Exception e) {
		}
		return returnValue;
	}

	private static boolean timeToQueryCDSForCert(String clientId) {
		String clientQueryKey = clientId + CDSCERTQUERYSUFFIX;
		Calendar currently = Calendar.getInstance();
		long now = currently.getTimeInMillis();
		if (keyStoreCache.containsKey(clientQueryKey)) {
			Map<String, CachedItem> tempCache = keyStoreCache.get(clientQueryKey);
			CachedItem item = tempCache.get(clientId);
			if (item == null) {
				logger.info(new FedExLogEntry("  No timestamp for a recent CDS query, allowing another."));
				return true;
			}
			Long timeStamp = (Long)item.getPayload();
			if (now - timeStamp.longValue() <= CDSCERTQUERYINTERVAL) {
				logger.info(new FedExLogEntry("  Recent CDS query, preventing another."));
				return false;
			}
			logger.info(new FedExLogEntry("  No recent CDS query, allowing another."));
			return true;
		}
		logger.info(new FedExLogEntry("  clientTokenCache doesn't contain " + clientQueryKey));
		return true;
	}

	private static boolean timeToLogFatal(String clientId) {
		String clientLogKey = clientId + FATALLOGSUFFIX;
		Calendar currently = Calendar.getInstance();
		long now = currently.getTimeInMillis();
		if (keyStoreCache.containsKey(clientLogKey)) {
			Map<String, CachedItem> tempCache = keyStoreCache.get(clientLogKey);
			CachedItem item = tempCache.get(clientId);
			if (item == null) {
				logger.info(new FedExLogEntry("  No timestamp for a recent CRITICAL log write, allowing another."));
				return true;
			}
			Long timeStamp = (Long)item.getPayload();
			if (now - timeStamp.longValue() <= FATALLOGINTERVAL) {
				logger.info(new FedExLogEntry("  Recent CRITICAL log write query, preventing another."));
				return false;
			}
			logger.info(new FedExLogEntry("   No recent CRITICAL log write query, allowing another."));
			return true;
		}
		logger.info(new FedExLogEntry("  clientTokenCache doesn't contain " + clientLogKey));
		return true;
	}

	private static void updateCacheFlag(String clientId, String suffix) {
		Map<String, CachedItem> tempCache = Collections.synchronizedMap(new HashMap());
		Calendar queryTime = Calendar.getInstance();
		long timeStamp = queryTime.getTimeInMillis();
		String clientQueryKey = clientId + suffix;
		int myMonth = 1 + queryTime.get(2);
		logger.info(new FedExLogEntry("Setting " + clientQueryKey + " flag to: " + myMonth + "/" + queryTime.get(5) + "/" + queryTime.get(1) + " " + queryTime.get(10) + ":" + queryTime.get(12) + ":" + queryTime.get(13) + "." + queryTime.get(14)));
		tempCache.put(clientId, new CachedItem(Long.valueOf(timeStamp)));
		keyStoreCache.put(clientQueryKey, tempCache);
	}

	public static boolean rotationCheck(String clientId) {
		boolean rotationDone = false;
		try {
			if (!KeystoreRotation.isBeanInit) {
				logger.debug(new FedExLogEntry("Rotation Check being called Bean is not initialized "));
				String cdsURL = KeystoreCipherProviderImpl.getInstance().getCDSUrl();
				if (StringUtils.isNullOrBlank(cdsURL)) {
					logger.error(new FedExLogEntry("The CDS URL was null : Keystore Rotation will not work as no CDS URL was specified"));
					return rotationDone;
				}
				logger.debug(new FedExLogEntry("Initializing keystore bean "));
				new KeystoreRotation(cdsURL);
			}
			KeystoreCipherProviderImpl.getInstance();
			KeystoreRotation.absolutePathOfCert = KeystoreCipherProviderImpl.absolutePathOfCert;
			KeystoreRotation.absolutePathOfClientFile = KeystoreCipherProviderImpl.absolutePathOfClientFile;
			Date certDate;
			if (("".equals(KeystoreCipherProviderImpl.absolutePathOfCert)) || ("".equals(KeystoreCipherProviderImpl.absolutePathOfClientFile))) {
				logger.error(new FedExLogEntry("client.properties cannot be resolved to an absolute file path because it does not reside on the file system"));
				certDate = KeystoreCipherProviderImpl.certExprDate;
			}
			else {
				certDate = KeystoreCipherProviderImpl.certExprDate;
			}
			if ((FedExAppFrameworkProperties.getInstance().isManagedEnvironment()) || (KeystoreCipherProviderImpl.getInstance().getAutoCertRotationFlag())) {
				checkForRotationDemandSemaphoreFile();
				getCertState(certDate);
				String state = keyStoreState.get("CERT_STATE");
				String level = keyStoreState.get("LOG_LEVEL");
				logger.info(new FedExLogEntry(" Keystore Rotation Check being called : The state of the cert is :" + state));
				if ((!"GOOD".equalsIgnoreCase(state)) || (demandRotation) || (configCheckonStartup)) {
					if (configCheckonStartup) {
						logger.always("First time bootstraping application: initializing certRotation configuation checks");
					}
					rotationDone = rotationHandler(clientId, state, level, certDate);
					if (rotationDone) {
						keyStoreState.put("CERT_STATE", "GOOD");
						keyStoreState.put("LOG_LEVEL", "INFO");
					}
					if ((demandRotation) &&
					    (!semaphoreFile.delete())) {
						logger.error("Certificate rotation (Spring) completed but trigger file [" + semaphoreFile.getAbsolutePath() + "] could not be removed.");
					}
				}
			}
			else {
				logger.always(new FedExLogEntry("The Security API detected that this is not a Managed Environment and the autocertrotation.flag = false is set in security.properties therefore Automated Certificate Rotation will not execute."));
			}
		}
		finally {
			configCheckonStartup = false;
		}
		return rotationDone;
	}

	public static boolean rotationCheckNonSpringApps(String clientId, String cdsURL, String certPath, String clientPropsPath) {
		boolean rotationDone = false;
		try {
			if ((StringUtils.isNullOrBlank(clientPropsPath)) || (StringUtils.isNullOrBlank(certPath)) || (StringUtils.isNullOrBlank(cdsURL))) {
				if (StringUtils.isNullOrBlank(cdsURL)) {
					logger.error(new FedExLogEntry("The CDS URL was null : Keystore Rotation will not work as no CDS URL was specified"));
				}
				else {
					logger.warn(new FedExLogEntry("The Security API is unable to get the absolute path for client.propeties and keystore"));
				}
				return rotationDone;
			}
			KeystoreRotation.absolutePathOfCert = certPath;
			KeystoreRotation.absolutePathOfClientFile = clientPropsPath;
			Date certDate = getCertExprDt(clientId);
			if ((FedExAppFrameworkProperties.getInstance().isManagedEnvironment()) || (KeystoreCipherProviderImpl.getInstance().getAutoCertRotationFlag())) {
				checkForRotationDemandSemaphoreFile();
				getCertState(certDate);
				String state = keyStoreState.get("CERT_STATE");
				String level = keyStoreState.get("LOG_LEVEL");
				logger.info(new FedExLogEntry(" Keystore Rotation Check being called : The state of the cert is :" + state));
				if ((!"GOOD".equalsIgnoreCase(state)) || (demandRotation) || (configCheckonStartup)) {
					new KeystoreRotation(cdsURL);
					rotationDone = rotationHandler(clientId, state, level, certDate);
					if (rotationDone) {
						keyStoreState.put("CERT_STATE", "GOOD");
						keyStoreState.put("LOG_LEVEL", "INFO");
					}
					if ((demandRotation) &&
					    (!semaphoreFile.delete())) {
						logger.error("Certificate rotation (non-Spring) completed but trigger file [" + semaphoreFile.getAbsolutePath() + "] could not be removed.");
					}
				}
			}
			else {
				logger.always(new FedExLogEntry("The Security API detected that this is not a Managed Environment and the autocertrotation.flag = false is set in security.properties therefore Automated Certificate Rotation will not execute."));
			}
		}
		finally {
			configCheckonStartup = false;
		}
		return rotationDone;
	}

	private static boolean rotationHandler(String clientId, String state, String logLevel, Date cacheExprDate) {
		boolean rotationDone = false;
		boolean rotateFlg = true;
		String message = "The certificate is set to expire at " + cacheExprDate.toGMTString();
		String localLogLevel = logLevel;
		if (demandRotation) {
			logger.always("On-demand rotation trigger file detected");
		}
		if (!KeystoreRotation.canWrite()) {
			message = message + ", unable to write to the cert directory";
			logHandler(localLogLevel, message, clientId);
			return rotationDone;
		}
		boolean queryCdsForNewCertFlag = false;
		if ((state.equalsIgnoreCase("EXPIRED")) || (state.equalsIgnoreCase("FATL"))) {
			queryCdsForNewCertFlag = true;
		}
		else {
			if ((timeToQueryCDSForCert(clientId)) || (demandRotation) || (configCheckonStartup)) {
				queryCdsForNewCertFlag = true;
			}
			else {
				message = " A recent query to CDS was done in the last 24 hours so quitting";
			}
		}
		if (isLockFileExist()) {
			try {
				Thread.sleep(300000L);
				if (!isLockFileExist()) {
					if (!compareCacheExprWithDiskExprDt(clientId)) {
						rotateFlg = false;
						logger.always(new FedExLogEntry("Waited for lock file to be removed and new / old certificate dates are not a match."));
					}
					else {
						logger.always(new FedExLogEntry("Waited for lock file to be removed and new / old certificate dates are a match."));
						rotateFlg = true;
					}
				}
			}
			catch (InterruptedException e) {
				logger.debug("Sleep was interupted", e);
			}
			catch (Exception e) {
				logger.debug("Exception", e);
			}
		}
		else {
			if (!compareCacheExprWithDiskExprDt(clientId)) {
				logger.always(new FedExLogEntry(" lock file not exist and dates are not match ."));
				rotateFlg = false;
			}
			else {
				logger.always(new FedExLogEntry(" lock file not exist and dates are match ."));
				rotateFlg = true;
			}
		}
		if (!rotateFlg) {
			try {
				if (KeystoreRotation.reloadCertFromDisk()) {
					rotationDone = true;
					localLogLevel = "INFO";
					message = "A new cert is found on the file systeam, reloaded the new cert.";
					logger.always(new FedExLogEntry("A new cert is found on the file systeam, reloaded the new cert."));
					KeystoreCipherProviderImpl.certExprDate = getCertExprDt(clientId);
				}
			}
			catch (Exception e) {
				logger.always(new FedExLogEntry(" Reload cert from disk is failed."), e);
			}
		}
		else {
			boolean lockFileCreated = false;
			try {
				if (createLockFile()) {
					lockFileCreated = true;
					if (queryCdsForNewCertFlag) {
						if (queryCDSForCert(cacheExprDate, clientId)) {
							message = "Cert from CDS found.. attempting to validate and rotate it to the filesystem.";
							if (KeystoreRotation.rotateCert()) {
								rotationDone = true;
								localLogLevel = "INFO";
								message = "Cert from CDS was retrieved & rotated into the file system.";
								auditLogger.info(new FedExLogEntry(new SimpleDateFormat("yyyyMMddhh24mmss").format(new Date()) + "|keystoreStanza|" + clientId + "|" + "943415_cds" + "|update|keystore"));
								logger.always(new FedExLogEntry("Inside  rotated ." + message));
							}
							else {
								message = "Current cert nearing expiration. Cert found in CDS but was invalid.";
								logger.always(new FedExLogEntry("Inside else cert rotated ." + message));
							}
						}
						else {
							if ((configCheckonStartup) && (forcePostRotationCheck)) {
								forcePostRotationCheck = false;
								logger.info("Checking Cert, CDS, and LDAP configuatiation");
								KeystoreRotation.tokenTester(clientId);
								rotationDone = true;
							}
							if (cdsCertFlag) {
								message = "Current cert nearing expiration and query to CDS was done but no keystore was found in CDS .";
							}
							else {
								message = "Current cert nearing expiration and the cert in CDS is invalid .";
							}
						}
					}
				}
				else {
					logger.always(new FedExLogEntry("Unable to create a lock file, waiting 5 minutes to see if another process completes a certificate rotation."));
					Thread.sleep(300000L);
					if (!isLockFileExist()) {
						if (!compareCacheExprWithDiskExprDt(clientId)) {
							logger.info(new FedExLogEntry(" lock file not exist and dates are not match ."));
							try {
								if (KeystoreRotation.reloadCertFromDisk()) {
									rotationDone = true;
									localLogLevel = "INFO";
									message = "A new cert is found on the file systeam, reloaded the new cert.";
									logger.always(new FedExLogEntry("A new cert is found on the file systeam, reloaded the new cert."));
									KeystoreCipherProviderImpl.certExprDate = getCertExprDt(clientId);
								}
							}
							catch (Exception e) {
								logger.always(new FedExLogEntry(" Reload cert from disk is failed."), e);
							}
						}
					}
					else {
						logger.always(new FedExLogEntry("Lock file still exists and it is not an hour old.  Will try again when the timer is called again."));
					}
				}
			}
			catch (Exception exc) {
				message = "Current cert nearing expiration. Cert found in CDS but was invalid. Exception: " + exc.getMessage();
			}
			finally {
				if (lockFileCreated) {
					deleteLockFile();
				}
			}
		}
		logHandler(localLogLevel, message, clientId);
		return rotationDone;
	}

	private static void logHandler(String logType, String message, String clientId) {
		if (configCheckonStartup) {
			logger.always(new FedExLogEntry(message));
		}
		else {
			if ((logType.equalsIgnoreCase("FATL")) && (timeToLogFatal(clientId))) {
				logger.fatal(new FedExLogEntry(message));
				updateCacheFlag(clientId, FATALLOGSUFFIX);
			}
			else {
				if (logType.equalsIgnoreCase("ERR")) {
					logger.error(new FedExLogEntry(message));
				}
				else {
					if (logType.equalsIgnoreCase("WARN")) {
						logger.warn(new FedExLogEntry(message));
					}
					else {
						if (logType.equalsIgnoreCase("INFO")) {
							logger.info(new FedExLogEntry(message));
						}
					}
				}
			}
		}
	}

	public static Date getCertExprDt(String clientId) {
		// Byte code:
		//   0: aconst_null
		//   1: astore_1
		//   2: getstatic 92	com/fedex/security/client/KeystoreRotation:absolutePathOfClientFile	Ljava/lang/String;
		//   5: invokestatic 177	com/fedex/security/common/FileLoader:getFileAsProperties	(Ljava/lang/String;)Ljava/util/Properties;
		//   8: astore_2
		//   9: aload_2
		//   10: invokestatic 178	com/fedex/security/utils/SecurityUtils:trimProperties	(Ljava/util/Properties;)V
		//   13: aload_2
		//   14: ldc -77
		//   16: invokevirtual 180	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   19: invokestatic 181	java/security/KeyStore:getInstance	(Ljava/lang/String;)Ljava/security/KeyStore;
		//   22: astore_3
		//   23: aload_2
		//   24: ldc -74
		//   26: invokevirtual 180	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   29: invokestatic 183	com/fedex/security/common/FileLoader:getFileAsInputStream	(Ljava/lang/String;)Ljava/io/InputStream;
		//   32: astore_1
		//   33: new 184	java/io/File
		//   36: dup
		//   37: aload_2
		//   38: ldc -74
		//   40: invokevirtual 180	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   43: invokespecial 185	java/io/File:<init>	(Ljava/lang/String;)V
		//   46: astore 4
		//   48: aload 4
		//   50: invokevirtual 186	java/io/File:getName	()Ljava/lang/String;
		//   53: putstatic 187	com/fedex/security/client/KeystoreRotation:fileName	Ljava/lang/String;
		//   56: getstatic 26	com/fedex/security/client/KeystoreExpirationCheck:logger	Lcom/fedex/framework/logging/FedExLoggerInterface;
		//   59: new 27	com/fedex/framework/logging/FedExLogEntry
		//   62: dup
		//   63: new 34	java/lang/StringBuilder
		//   66: dup
		//   67: invokespecial 35	java/lang/StringBuilder:<init>	()V
		//   70: ldc -68
		//   72: invokevirtual 37	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   75: getstatic 187	com/fedex/security/client/KeystoreRotation:fileName	Ljava/lang/String;
		//   78: invokevirtual 37	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   81: invokevirtual 40	java/lang/StringBuilder:toString	()Ljava/lang/String;
		//   84: invokespecial 29	com/fedex/framework/logging/FedExLogEntry:<init>	(Ljava/lang/String;)V
		//   87: invokeinterface 30 2 0
		//   92: aload_3
		//   93: aload_1
		//   94: aload_2
		//   95: ldc -67
		//   97: invokevirtual 180	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   100: invokevirtual 190	java/lang/String:toCharArray	()[C
		//   103: invokevirtual 191	java/security/KeyStore:load	(Ljava/io/InputStream;[C)V
		//   106: new 192	java/security/KeyStore$PasswordProtection
		//   109: dup
		//   110: aload_2
		//   111: ldc -63
		//   113: invokevirtual 180	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   116: invokevirtual 190	java/lang/String:toCharArray	()[C
		//   119: invokespecial 194	java/security/KeyStore$PasswordProtection:<init>	([C)V
		//   122: astore 5
		//   124: aload_3
		//   125: aload_2
		//   126: ldc -61
		//   128: invokevirtual 180	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   131: aload 5
		//   133: invokevirtual 196	java/security/KeyStore:getEntry	(Ljava/lang/String;Ljava/security/KeyStore$ProtectionParameter;)Ljava/security/KeyStore$Entry;
		//   136: checkcast 197	java/security/KeyStore$PrivateKeyEntry
		//   139: astore 6
		//   141: aload 6
		//   143: invokevirtual 198	java/security/KeyStore$PrivateKeyEntry:getCertificate	()Ljava/security/cert/Certificate;
		//   146: invokevirtual 199	java/security/cert/Certificate:getEncoded	()[B
		//   149: invokestatic 200	javax/security/cert/X509Certificate:getInstance	([B)Ljavax/security/cert/X509Certificate;
		//   152: invokevirtual 201	javax/security/cert/X509Certificate:getNotAfter	()Ljava/util/Date;
		//   155: astore 7
		//   157: aload_1
		//   158: ifnull +7 -> 165
		//   161: aload_1
		//   162: invokevirtual 202	java/io/InputStream:close	()V
		//   165: aload 7
		//   167: areturn
		//   168: astore 8
		//   170: aload_1
		//   171: ifnull +7 -> 178
		//   174: aload_1
		//   175: invokevirtual 202	java/io/InputStream:close	()V
		//   178: aload 8
		//   180: athrow
		//   181: astore_1
		//   182: new 34	java/lang/StringBuilder
		//   185: dup
		//   186: invokespecial 35	java/lang/StringBuilder:<init>	()V
		//   189: ldc -53
		//   191: invokevirtual 37	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   194: aload_0
		//   195: invokevirtual 37	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   198: invokevirtual 40	java/lang/StringBuilder:toString	()Ljava/lang/String;
		//   201: astore_2
		//   202: getstatic 26	com/fedex/security/client/KeystoreExpirationCheck:logger	Lcom/fedex/framework/logging/FedExLoggerInterface;
		//   205: new 27	com/fedex/framework/logging/FedExLogEntry
		//   208: dup
		//   209: aload_2
		//   210: invokespecial 29	com/fedex/framework/logging/FedExLogEntry:<init>	(Ljava/lang/String;)V
		//   213: aload_1
		//   214: invokeinterface 204 3 0
		//   219: new 205	java/lang/RuntimeException
		//   222: dup
		//   223: aload_2
		//   224: aload_1
		//   225: invokespecial 206	java/lang/RuntimeException:<init>	(Ljava/lang/String;Ljava/lang/Throwable;)V
		//   228: athrow
		// Line number table:
		//   Java source line #804	-> byte code offset #0
		//   Java source line #808	-> byte code offset #2
		//   Java source line #810	-> byte code offset #9
		//   Java source line #812	-> byte code offset #13
		//   Java source line #814	-> byte code offset #23
		//   Java source line #816	-> byte code offset #33
		//   Java source line #818	-> byte code offset #48
		//   Java source line #819	-> byte code offset #56
		//   Java source line #831	-> byte code offset #92
		//   Java source line #833	-> byte code offset #106
		//   Java source line #836	-> byte code offset #124
		//   Java source line #840	-> byte code offset #141
		//   Java source line #845	-> byte code offset #157
		//   Java source line #847	-> byte code offset #161
		//   Java source line #845	-> byte code offset #168
		//   Java source line #847	-> byte code offset #174
		//   Java source line #853	-> byte code offset #181
		//   Java source line #855	-> byte code offset #182
		//   Java source line #857	-> byte code offset #202
		//   Java source line #858	-> byte code offset #219
		// Local variable table:
		//   start	length	slot	name	signature
		//   0	229	0	clientId	String
		//   1	174	1	inputFile	java.io.InputStream
		//   181	44	1	e	Exception
		//   8	118	2	props	java.util.Properties
		//   201	23	2	msg	String
		//   22	103	3	clientKeyStore	java.security.KeyStore
		//   46	3	4	tempFile	File
		//   122	10	5	keyPassword	java.security.KeyStore.PasswordProtection
		//   139	3	6	pkEntry	java.security.KeyStore.PrivateKeyEntry
		//   168	11	8	localObject	Object
		// Exception table:
		//   from	to	target	type
		//   2	157	168	finally
		//   168	170	168	finally
		//   0	165	181	java/lang/Exception
		//   168	181	181	java/lang/Exception
		return new Date();
	}

	public static void handleFatalLogs(String clientId) {
		String logType = keyStoreState.get("LOG_LEVEL");
		if ((logType != null) && (logType.equalsIgnoreCase("FATL")) && (timeToLogFatal(clientId))) {
			logger.fatal(new FedExLogEntry("The state of the cert is FATAL, no rotation has happend."));
			updateCacheFlag(clientId, FATALLOGSUFFIX);
		}
	}

	private static boolean isLockFileExist() {
		File ClientPropertiesPath = new File(KeystoreRotation.absolutePathOfClientFile);
		File defaultDir = new File(ClientPropertiesPath.getParent());
		File tempLoc = new File(defaultDir.getAbsolutePath() + File.separator + "/" + certRotationLckFile);
		boolean exists = tempLoc.exists();
		logger.debug(new FedExLogEntry("Inside is lockfile exists.  Exists: " + tempLoc.exists() + ", can write: " + tempLoc.canWrite()));
		if ((exists) && (new Date().getTime() - tempLoc.lastModified() > 3600000L)) {
			try {
				if (tempLoc.delete()) {
					exists = tempLoc.exists();
					logger.debug(new FedExLogEntry("Deleted the old lockfile exists.  Exists: " + tempLoc.exists() + ", can write: " + tempLoc.canWrite()));
				}
				else {
					exists = tempLoc.exists();
					logger.debug(new FedExLogEntry("Unable to delete the old lockfile exists.  Exists: " + tempLoc.exists() + ", can write: " + tempLoc.canWrite()));
				}
			}
			catch (Exception e) {
				logger.error("Unable to delete the lock file '" + certRotationLckFile + "' for certificate rotation", e);
			}
		}
		return exists;
	}

	private static boolean compareCacheExprWithDiskExprDt(String clientId) {
		boolean flag = false;
		if (KeystoreCipherProviderImpl.certExprDate.equals(getCertExprDt(clientId))) {
			flag = true;
		}
		logger.debug(new FedExLogEntry("Inside compare CacheExprWithDiskExprDt ." + flag));
		return flag;
	}

	private static boolean createLockFile() {
		boolean createFlg = false;
		File ClientPropertiesPath = new File(KeystoreRotation.absolutePathOfClientFile);
		File defaultDir = new File(ClientPropertiesPath.getParent());
		File lockFile = new File(defaultDir.getAbsolutePath() + File.separator + "/" + certRotationLckFile);
		if (lockFile.exists()) {
			logger.always("Inside create lock file ,Lock file exists.");
			if (new Date().getTime() - lockFile.lastModified() > 3600000L) {
				try {
					lockFile.delete();
				}
				catch (Exception e) {
					logger.error("Unable to delete the lock file '" + certRotationLckFile + "' for certificate rotation", e);
				}
			}
			else {
				logger.always("Inside create lock file ,and it is less than an hour old.");
			}
		}
		if (!lockFile.exists()) {
			try {
				if (lockFile.createNewFile()) {
					createFlg = true;
				}
			}
			catch (Exception e) {
				if (lockFile.exists()) {
					logger.debug("Caught an exception when creating the lock file '" + certRotationLckFile + "' for certificate rotation.  This can be ignored if another machine is performing certificate rotation at this time", e);
				}
				else {
					logger.always("Unable to create the lock file '" + certRotationLckFile + "' for certificate rotation", e);
				}
			}
		}
		logger.debug(new FedExLogEntry("Inside create lock file, lock file created ." + createFlg));
		return createFlg;
	}

	private static void deleteLockFile() {
		File ClientPropertiesPath = new File(KeystoreRotation.absolutePathOfClientFile);
		File defaultDir = new File(ClientPropertiesPath.getParent());
		File lockFile = new File(defaultDir.getAbsolutePath() + File.separator + "/" + certRotationLckFile);
		try {
			lockFile.delete();
		}
		catch (Exception e) {
			logger.error("Unable to delete the lock file '" + certRotationLckFile + "' after certificate rotation completed", e);
		}
		logger.always(new FedExLogEntry("Inside delete lock file, lock file deleted ."));
	}

	public static void checkForRotationDemandSemaphoreFile() {
		String semaphoreDir = null;
		demandRotation = false;
		if (StringUtils.isNullOrBlank(KeystoreRotation.absolutePathOfClientFile)) {
			logger.error("Certificate rotation is enabled but bootstrap has not been initialized.");
		}
		else {
			semaphoreDir = FileLoader.getFile(KeystoreRotation.absolutePathOfClientFile).getParent();
			semaphoreFile = new File(semaphoreDir + File.separator + DEMANDSEMAPHORE);
			if ((semaphoreFile != null) && (semaphoreFile.exists())) {
				if (semaphoreFile.isDirectory()) {
					logger.fatal("Found on-demand rotation trigger but as a directory; trigger must be a file. Rotation demand ignored.");
				}
				else {
					if (!semaphoreFile.canWrite()) {
						logger.fatal("Found on-demand rotation trigger file is not writable. Rotation demand ignored.");
					}
					else {
						if (!KeystoreCipherProviderImpl.getInstance().getAutoCertRotationFlag()) {
							logger.fatal("Found on-demand rotation trigger file but autocertrotation.flag is set to false. Rotation demand ignored.");
						}
						else {
							logger.always("Found on-demand rotation trigger file, rotation enabled");
							demandRotation = true;
						}
					}
				}
			}
		}
	}

	public static String completeCertRotation() {
		String message = "";
		boolean lockFileCreated = false;
		if ((FedExAppFrameworkProperties.getInstance().isManagedEnvironment()) || (KeystoreCipherProviderImpl.getInstance().getAutoCertRotationFlag())) {
			if (!isLockFileExist()) {
				try {
					if (!KeystoreRotation.canWrite()) {
						message = "unable to write to the cert directory";
						logger.always(new FedExLogEntry(message));
					}
					else {
						if (KeystoreRotation.getCDSCertExpirationDate() == null) {
							message = "Failed to get the expiration date of the new cert from CDS.";
							logger.warn(new FedExLogEntry(message));
						}
						else {
							if (!KeystoreRotation.getCDSCertExpirationDate().equals(KeystoreCipherProviderImpl.certExprDate)) {
								if (createLockFile()) {
									lockFileCreated = true;
									if (KeystoreRotation.rotateCert()) {
										message = "Cert from CDS was retrieved & rotated into the file system.";
										logger.always(new FedExLogEntry(message));
									}
									else {
										message = "Certificate rotation did NOT occur. Check log messages for more details.";
										logger.always(new FedExLogEntry(message));
									}
								}
								else {
									message = "lock file exist. Cert rotation will NOT occur. Try again later.";
									logger.always(new FedExLogEntry(message));
								}
							}
							else {
								message = "Certificate rotation did NOT occur. Certificate on file system matches latest in CDS.";
							}
						}
					}
				}
				catch (Exception e) {
					message = "Certificate rotation did NOT occur. Check log messages for more details." + e.getMessage();
					logger.error(message + " Exception: ", e);
				}
			}
			else {
				message = "lock file exist. Cert rotation will NOT occur. Try again later.";
				logger.always(new FedExLogEntry(message));
			}
		}
		else {
			message = "The Security API detected that this is not a Managed Environment and the autocertrotation.flag = false is set in security.properties therefore Automated Certificate Rotation will not execute.";
			logger.always(new FedExLogEntry(message));
		}
		if (lockFileCreated) {
			deleteLockFile();
		}
		return message;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\client\KeystoreExpirationCheck.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */