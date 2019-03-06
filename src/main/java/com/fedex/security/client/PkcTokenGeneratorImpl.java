package com.fedex.security.client;

import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import com.fedex.framework.utility.FedExAppFrameworkProperties;
import com.fedex.security.common.CachedItem;
import com.fedex.security.common.CipherProvider;
import com.fedex.security.common.FileLoader;
import com.fedex.security.common.StringUtils;
import com.fedex.security.exceptions.SecurityConfigurationException;
import com.fedex.security.utils.SecurityUtils;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

public final class PkcTokenGeneratorImpl
		implements TokenGenerator {
	public static final String TOKEN_VERSION = "v1";
	public static final String TOKEN_MAX_TTL_IN_SECONDS_PROP = "security.api.token.max.ttl";
	public static final String TOKEN_SAFE_TTL_IN_SECONDS_PROP = "security.api.token.safe.ttl";
	public static final String TOKEN_EXPIRATION_CHECK_IN_SECONDS_PROP = "security.api.token.expiration.check";
	public static final String CLIENT_KEYSTORE_FILE_PROP = "client.keystore.file";
	public static final String CLIENT_KEYSTORE_PASS_PROP = "client.keystore.password";
	public static final String CLIENT_KEYSTORE_KEY_ALIAS_PROP = "client.keystore.key.alias";
	public static final String CLIENT_PRIVATE_KEY_PASS_PROP = "client.private.key.password";
	public static final String CLIENT_KEYSTORE_TYPE = "client.keystore.type";
	public static final String CERT_ROTATION_TIME = "security.api.cert.rotation.time";
	private static final long ONCE_PER_DAY = 86400000L;
	private static final String DEFAULT_CERT_ROTATION_TIME = "06:00:00";
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(PkcTokenGeneratorImpl.class.getName());
	private static boolean rotateOnStartup = true;
	private static boolean firstTimeRotate = true;
	private static Timer expirationTimer = null;
	private static long expirationSerial = 0L;
	private static Timer rotationTimer = null;
	private static long rotationSerial = 0L;
	private long tokenMaxTtlInSeconds;
	private long tokenSafeTtlInSeconds;
	private long tokenExpirationCheckInSeconds;
	private Map<String, Map<String, CachedItem>> clientTokenCache;
	private String certRotationTime = "";

	private PkcTokenGeneratorImpl() {
		this("security.properties");
	}

	private PkcTokenGeneratorImpl(String pathWithPropsFileName) {
		Properties props = null;
		try {
			props = FileLoader.getFileAsProperties(pathWithPropsFileName);
		}
		catch (RuntimeException re) {
			FileLoader.alwaysLogFiles(pathWithPropsFileName);
			String msg = "Could not load the security.Properties file '" + pathWithPropsFileName + "'. Please verify the file exists at the absolute location or in the classpath.";
			logger.fatal(msg);
			throw new RuntimeException(msg, re);
		}
		StringBuilder error = new StringBuilder();
		if (!props.containsKey("security.api.token.max.ttl")) {
			error.append("Failed to configure generator due to missing property security.api.token.max.ttl in security.properties file, exiting.");
		}
		if (!props.containsKey("security.api.token.safe.ttl")) {
			error.append("Failed to configure generator due to missing property security.api.token.safe.ttl in security.properties file, exiting.");
		}
		if (!props.containsKey("security.api.token.expiration.check")) {
			error.append("Failed to configure generator due to missing property security.api.token.expiration.check in security.properties file, exiting.");
		}
		if (error.length() != 0) {
			logger.fatal(new FedExLogEntry(error.toString()));
			throw new RuntimeException(error.toString());
		}
		try {
			this.tokenMaxTtlInSeconds = Long.parseLong(props.getProperty("security.api.token.max.ttl"));
			this.tokenSafeTtlInSeconds = Long.parseLong(props.getProperty("security.api.token.safe.ttl"));
			this.tokenExpirationCheckInSeconds = Long.parseLong(props.getProperty("security.api.token.expiration.check"));
			logger.info(new FedExLogEntry("PkcTokenGeneratorImpl instance created"));
			this.certRotationTime = props.getProperty("security.api.cert.rotation.time");
			logger.info(new FedExLogEntry("certRotationTime " + this.certRotationTime));
			if (StringUtils.isNullOrBlank(this.certRotationTime)) {
				this.certRotationTime = "06:00:00";
				String msg = "Cert rotation time is not provided in security.properties, defaulting cert rotation time to 6:00AM GMT";
				logger.warn(new FedExLogEntry("Cert rotation time is not provided in security.properties, defaulting cert rotation time to 6:00AM GMT"));
			}
			else {
				if (invalidTime(this.certRotationTime)) {
					logger.info(new FedExLogEntry("certRotationTime " + this.certRotationTime));
					this.certRotationTime = "06:00:00";
					String msg = "Cert rotation time provided in security.properties is invalid defaulting cert rotation time to 6:00AM GMT";
					logger.warn(new FedExLogEntry("Cert rotation time provided in security.properties is invalid defaulting cert rotation time to 6:00AM GMT"));
				}
			}
			this.clientTokenCache = Collections.synchronizedMap(new HashMap());
			logger.info(new FedExLogEntry("Caches initialized"));
			ClientCipherProviderFactory.getProvider().setRotationCallback(new RotationCallbackImpl());
		}
		catch (Exception e) {
			String msg = "Failed to configure generator due to invalid values provided for properties, exiting. Verify content of security.properties";
			logger.fatal(new FedExLogEntry("Failed to configure generator due to invalid values provided for properties, exiting. Verify content of security.properties"), e);
			throw new RuntimeException("Failed to configure generator due to invalid values provided for properties, exiting. Verify content of security.properties", e);
		}
	}

	public static final PkcTokenGeneratorImpl getInstance() {
		return PkcTokenGeneratorImplHolder.getInstance();
	}

	public static final PkcTokenGeneratorImpl getInstance(String propsFile) {
		return PkcTokenGeneratorImplHolder.getInstance(propsFile);
	}

	protected static final String getClientIdFromFingerPrint() {
		String clientId = FedExAppFrameworkProperties.getInstance().getAppId();
		if ((clientId == null) || (clientId.trim().equals(""))) {
			clientId = "APP";
		}
		if (clientId.matches("^APP[0-9]*[1-9][0-9]*$")) {
			return clientId;
		}
		if (clientId.matches("^[0-9]*[1-9][0-9]*$")) {
			return "APP" + clientId;
		}
		logger.fatal(new FedExLogEntry("Invalid app.id in the fp.properties file; token generation is not available."));
		throw new SecurityConfigurationException("Unable to determine application id (check app.id), unable to generate tokens!");
	}

	public static void cancelExpirationTimer() {
		if (expirationTimer != null) {
			expirationTimer.cancel();
		}
	}

	public static void cancelRotationTimer() {
		if (rotationTimer != null) {
			rotationTimer.cancel();
		}
	}

	private static boolean invalidTime(String timeStr) {
		String st = timeStr;
		if (st != null) {
			st = st.replaceAll("\\s", "");
		}
		String regex = "^(([0]?[0-9])|([1]?[0-9])|([2]?[0-4])):(([0-5][0-9])):([0-5][0-9])";
		return !Pattern.matches(regex, st);
	}

	public final void configure() {
		configure(getClientIdFromFingerPrint(), "client.properties");
	}

	public final void configure(String propsFileName) {
		configure(getClientIdFromFingerPrint(), propsFileName);
	}

	public final void configure(String clientId, String propsFileName) {
		Properties props = null;
		try {
			props = FileLoader.getFileAsProperties(propsFileName);
			SecurityUtils.trimProperties(props);
		}
		catch (RuntimeException re) {
			FileLoader.alwaysLogFiles(propsFileName);
			String msg = "Could not load the client.Properties file '" + propsFileName + "'. Please verify the file exists at the absolute location or in the classpath.";
			logger.fatal(msg);
			throw new RuntimeException(msg, re);
		}
		try {
			ClientCipherProviderFactory.getProvider().configure(clientId, props);
			if (rotateOnStartup) {
				try {
					if ((FedExAppFrameworkProperties.getInstance().isManagedEnvironment()) || (KeystoreCipherProviderImpl.getInstance().getAutoCertRotationFlag())) {
						synchronized (this) {
							if (firstTimeRotate) {
								firstTimeRotate = false;
								if (!KeystoreExpirationCheck.rotationCheck(getClientIdFromFingerPrint())) {
									logger.fatal(new FedExLogEntry("Configuration for certificate rotation is not set correctly. Please make sure the application is able to connect to the correct LDAP and CDS url inside security.properties. Check log messages for more details."));
									throw new RuntimeException("!!!!!!!!!Error with the Configuration for Cert-Rotation!!!!!!!");
								}
							}
						}
					}
					else {
						logger.always(new FedExLogEntry("The Security API detected that this is not a Managed Environment and the autocertrotation.flag = false is set in security.properties therefore Automated Certificate Rotation will not execute."));
					}
				}
				finally {
					rotateOnStartup = false;
				}
			}
			manageTimers();
		}
		catch (SecurityConfigurationException sce) {
			String msg = "Failed to configure generator for client " + clientId;
			logger.fatal(new FedExLogEntry(msg));
			throw new RuntimeException(msg, sce);
		}
		catch (Exception e) {
			String msg = "Exception encountered configuring generator for client " + clientId;
			logger.fatal(new FedExLogEntry(msg));
			throw new RuntimeException(msg, e);
		}
	}

	public final boolean isConfigured(String clientId) {
		try {
			return ClientCipherProviderFactory.getProvider().isConfigured(clientId);
		}
		catch (SecurityConfigurationException sce) {
		}
		return false;
	}

	public final String getTokenForClientId(String clientId, String serviceName, String authzId) {
		return getTokenForClientId(clientId, serviceName, authzId, false);
	}

	public final String getTokenForClientId(String clientId, String serviceName, String authzId, boolean ignoreCache) {
		return constructToken(clientId, serviceName, authzId, ignoreCache);
	}

	public final String getToken(String serviceName, String authzId) {
		return getToken(serviceName, authzId, false);
	}

	public final String getToken(String serviceName, String authzId, boolean ignoreCache) {
		return getTokenForClientId(getClientIdFromFingerPrint(), serviceName, authzId, ignoreCache);
	}

	public final String getTokenForClientId(String clientId, String serviceName) {
		return getTokenForClientId(clientId, serviceName, false);
	}

	public final String getTokenForClientId(String clientId, String serviceName, boolean ignoreCache) {
		return constructToken(clientId, serviceName, null, ignoreCache);
	}

	public final String getToken(String serviceName) {
		return getToken(serviceName, false);
	}

	public final String getToken(String serviceName, boolean ignoreCache) {
		return getTokenForClientId(getClientIdFromFingerPrint(), serviceName, ignoreCache);
	}

	public final String getChainedToken(String token, String serviceName) {
		return getChainedToken(token, serviceName, false);
	}

	public final String getChainedToken(String token, String serviceName, boolean ignoreCache) {
		return getChainedTokenForClientId(getClientIdFromFingerPrint(), token, serviceName);
	}

	public final String getChainedTokenForClientId(String clientId, String token, String serviceName) {
		return getChainedTokenForClientId(clientId, token, serviceName, false);
	}

	public final String getChainedTokenForClientId(String clientId, String token, String serviceName, boolean ignoreCache) {
		if ((token == null) || (token.split(":").length != 4)) {
			String msg = "Invalid token provided to getChainedTokenForClientId method. Possibly null or malformed token. Check input and retry request.";
			logger.warn(new FedExLogEntry("Invalid token provided to getChainedTokenForClientId method. Possibly null or malformed token. Check input and retry request."));
			throw new RuntimeException("Invalid token provided to getChainedTokenForClientId method. Possibly null or malformed token. Check input and retry request.");
		}
		String[] tokenContents = token.split(":");
		String authzIdFromToken = tokenContents[3];
		return constructToken(clientId, serviceName, authzIdFromToken, ignoreCache);
	}

	private final void manageTimers() {
		if (!rotateOnStartup) {
			if (expirationSerial < System.currentTimeMillis() - 1.5D * this.tokenExpirationCheckInSeconds * 1000.0D) {
				if (expirationTimer != null) {
					expirationTimer.cancel();
				}
				expirationTimer = null;
				expirationTimer = new Timer(true);
				expirationTimer.schedule(new TokenExpirationTask(), this.tokenExpirationCheckInSeconds * 1000L, this.tokenExpirationCheckInSeconds * 1000L);
				expirationSerial = System.currentTimeMillis();
				logger.info(new FedExLogEntry("Token Expiration timer (re)started"));
			}
			else {
				logger.trace(new FedExLogEntry("Rotation timer status OK"));
			}
			if (rotationSerial < System.currentTimeMillis() - 86400000L) {
				if (rotationTimer != null) {
					rotationTimer.cancel();
				}
				rotationTimer = null;
				try {
					rotationTimer = new Timer(true);
					rotationTimer.schedule(new CertRotationTimerTask(), convertStringTimeToDate(this.certRotationTime), 86400000L);
					rotationSerial = System.currentTimeMillis();
				}
				catch (Exception e) {
					logger.trace(new FedExLogEntry("Exception occured Cert Rotation timer ", e.getMessage()));
				}
				logger.trace(new FedExLogEntry("Cert Rotation timer status OK"));
			}
		}
	}

	private final String constructToken(String clientId, String serviceName, String authzId, boolean ignoreCache) {
		if (!isConfigured(clientId)) {
			String msg = "The instance has not been configured for client " + clientId + ", the configure() method must be called for each client before using the generator.";
			logger.fatal(new FedExLogEntry(msg));
			throw new RuntimeException(msg);
		}
		return "v1:" + clientId + ":" + encryptToken(clientId, serviceName, ignoreCache) + ":" + (authzId == null ? clientId : authzId);
	}

	private final String encryptToken(String clientId, String serviceName, boolean ignoreCache) {
		String cachedToken;
		if ((!ignoreCache) && ((cachedToken = getCachedToken(clientId, serviceName)) != null)) {
			return cachedToken;
		}
		try {
			long createTimestamp = System.currentTimeMillis();
			Cipher cipher = ClientCipherProviderFactory.getProvider().getEncryptionCipher(clientId);
			String cipherText = "";
			synchronized (cipher) {
				if ((!ignoreCache) && ((cachedToken = getCachedToken(clientId, serviceName)) != null)) {
					return cachedToken;
				}
				byte[] cipherBytes = cipher.doFinal((serviceName + ":" + createTimestamp).getBytes(StandardCharsets.UTF_8));
				cipherText = new BASE64Encoder().encode(cipherBytes);
				cacheToken(clientId, serviceName, cipherText);
			}
			logger.debug(new FedExLogEntry("Generated new token, clientId = " + clientId, " serviceName=" + serviceName));
			return cipherText;
		}
		catch (Exception e) {
			String msg = "Unable to create an encrypted token for the client " + clientId + ", service " + serviceName;
			logger.fatal(new FedExLogEntry(msg));
			throw new RuntimeException(msg, e);
		}
	}

	public void logCertState(String appID, Date certExprDate) {
		if (certExprDate == null) {
			logger.fatal("Received NULL certificate expiration date when checking and logging the number of days to expiration");
			return;
		}
		StringBuilder logBuilder = new StringBuilder();
		logBuilder.append("Expiration Date of the ");
		checkAppIDToLog(appID, logBuilder);
		logBuilder.append(" Certificate on the filesytem is (");
		logBuilder.append(certExprDate);
		logBuilder.append(")");
		logger.always(logBuilder.toString());
		Date now = Calendar.getInstance().getTime();
		if (certExprDate.compareTo(now) < 1) {
			logBuilder.setLength(0);
			checkAppIDToLog(appID, logBuilder);
			logBuilder.append(" Certificate Expired, expiration Date of the certificate on the filesytem is (");
			logBuilder.append(certExprDate);
			logBuilder.append(")");
			logger.fatal(logBuilder.toString());
		}
		else {
			long certValidTime = certExprDate.getTime() - now.getTime();
			float certValidDays = (float)certValidTime / (float)TimeUnit.DAYS.toMillis(1L);
			float andHours = (float)(certValidTime % TimeUnit.DAYS.toMillis(1L)) / (float)TimeUnit.HOURS.toMillis(1L);
			logBuilder.setLength(0);
			checkAppIDToLog(appID, logBuilder);
			logBuilder.append(" Certificate is expiring in (");
			logBuilder.append((int)certValidDays);
			logBuilder.append(" days and ");
			logBuilder.append(andHours);
			logBuilder.append(" hours)");
			StringBuilder rotationAlertLog = null;
			if ((!FedExAppFrameworkProperties.getInstance().isManagedEnvironment()) && (!KeystoreCipherProviderImpl.getInstance().getAutoCertRotationFlag())) {
				rotationAlertLog = new StringBuilder();
				rotationAlertLog.append("The Security API detected that this is not a Managed Environment and ");
				rotationAlertLog.append("the autocertrotation.flag = false is set in security.properties ");
				rotationAlertLog.append("therefore Automated Certificate Rotation will not execute.");
			}
			switch (CertExprRange.getValue(certValidDays)) {
				case GOOD:
					logger.debug(logBuilder.toString());
					if (rotationAlertLog != null) {
						logger.debug(rotationAlertLog.toString());
					}
					break;
				case DAYS_40:
					logger.info(logBuilder.toString());
					if (rotationAlertLog != null) {
						logger.info(rotationAlertLog.toString());
					}
					break;
				case DAYS_30:
					logger.warn(logBuilder.toString());
					if (rotationAlertLog != null) {
						logger.warn(rotationAlertLog.toString());
					}
					break;
				case DAYS_14:
					logger.error(logBuilder.toString());
					if (rotationAlertLog != null) {
						logger.error(rotationAlertLog.toString());
					}
					break;
				case DAYS_7:
					logger.fatal(logBuilder.toString());
					if (rotationAlertLog != null) {
						logger.fatal(rotationAlertLog.toString());
					}
					break;
				default:
					logger.always(logBuilder.toString());
					if (rotationAlertLog != null) {
						logger.always(rotationAlertLog.toString());
					}
					break;
			}
		}
	}

	private void checkAppIDToLog(String appID, StringBuilder logBuilder) {
		logBuilder.append((appID != null) && (!appID.isEmpty()) ? appID : "");
		logBuilder.append((appID != null) && (!appID.isEmpty()) ? " Application" : "Application");
	}

	private final void cacheToken(String clientId, String serviceName, String cipherText) {
		Date cacheExprDate = KeystoreCipherProviderImpl.certExprDate;
		Date certExprDate = getCertExpiredDt(clientId);
		logCertState(clientId, certExprDate);
		if ((certExprDate != null) && (cacheExprDate != null)) {
			if (!certExprDate.after(new Date())) {
				if (cacheExprDate.equals(certExprDate)) {
					String msg = "The identity certificate for client " + clientId + " has expired, exiting.";
					logger.fatal(new FedExLogEntry(msg));
					throw new SecurityConfigurationException(msg);
				}
				Properties props = null;
				try {
					props = FileLoader.getFileAsProperties(KeystoreCipherProviderImpl.absolutePathOfClientFile);
					SecurityUtils.trimProperties(props);
				}
				catch (RuntimeException re) {
					FileLoader.alwaysLogFiles(KeystoreCipherProviderImpl.absolutePathOfClientFile);
					String msg = "Could not load the clientProperties file '" + KeystoreCipherProviderImpl.absolutePathOfClientFile + "'.  Please verify the file exists at the absolute location or in the classpath.";
					logger.fatal(msg);
					throw new RuntimeException(msg, re);
				}
				ClientCipherProviderFactory.getProvider().configure(clientId, props);
				ClientCipherProviderFactory.getProvider().getEncryptionCipher(clientId, true);
				ClientCipherProviderFactory.getProvider().setRotationCallback(new RotationCallbackImpl());
				Map<String, CachedItem> cache = Collections.synchronizedMap(new HashMap());
				logger.debug(new FedExLogEntry("The identity certificate was found to be expired and has been replaced with a new certificate found in CDS."));
			}
			else {
				if (!cacheExprDate.equals(getCertExpiredDt(clientId))) {
					Properties props = null;
					try {
						props = FileLoader.getFileAsProperties(KeystoreCipherProviderImpl.absolutePathOfClientFile);
						SecurityUtils.trimProperties(props);
					}
					catch (RuntimeException re) {
						FileLoader.alwaysLogFiles(KeystoreCipherProviderImpl.absolutePathOfClientFile);
						String msg = "Could not load the clientProperties file '" + KeystoreCipherProviderImpl.absolutePathOfClientFile + "'.  Please verify the file exists at the absolute location or in the classpath.";
						logger.fatal(msg);
						throw new RuntimeException(msg, re);
					}
					ClientCipherProviderFactory.getProvider().configure(clientId, props);
					ClientCipherProviderFactory.getProvider().getEncryptionCipher(clientId, true);
					ClientCipherProviderFactory.getProvider().setRotationCallback(new RotationCallbackImpl());
					Map<String, CachedItem> cache = Collections.synchronizedMap(new HashMap());
					logger.debug(new FedExLogEntry("The current identity certificate was nearing expiration and has been replaced with a new one found is CDS."));
				}
			}
		}
		synchronized (this.clientTokenCache) {
			Map<String, CachedItem> cache;
			if (this.clientTokenCache.containsKey(clientId)) {
				cache = this.clientTokenCache.get(clientId);
			}
			else {
				cache = Collections.synchronizedMap(new HashMap());
			}
			cache.put(serviceName, new CachedItem(cipherText, this.tokenMaxTtlInSeconds * 1000L));
			this.clientTokenCache.put(clientId, cache);
		}
		logger.trace(new FedExLogEntry("Caching token for client = " + clientId + ", service =" + serviceName));
	}

	private final String getCachedToken(String clientId, String serviceName) {
		manageTimers();
		if (!this.clientTokenCache.containsKey(clientId)) {
			return null;
		}
		Map<String, CachedItem> tokenCache = this.clientTokenCache.get(clientId);
		if (tokenCache.containsKey(serviceName)) {
			CachedItem item = tokenCache.get(serviceName);
			if (!item.isExpired()) {
				logger.trace(new FedExLogEntry("Used cached token for client " + clientId + ", service " + serviceName));
				return (String)item.getPayload();
			}
		}
		return null;
	}

	public Date getCertExpiredDt(String clientId)
			throws SecurityConfigurationException {
		// Byte code:
		//   0: aconst_null
		//   1: astore_2
		//   2: getstatic 187	com/fedex/security/client/KeystoreCipherProviderImpl:absolutePathOfClientFile	Ljava/lang/String;
		//   5: invokestatic 44	com/fedex/security/common/StringUtils:isNullOrBlank	(Ljava/lang/String;)Z
		//   8: ifne +13 -> 21
		//   11: getstatic 187	com/fedex/security/client/KeystoreCipherProviderImpl:absolutePathOfClientFile	Ljava/lang/String;
		//   14: invokestatic 13	com/fedex/security/common/FileLoader:getFileAsProperties	(Ljava/lang/String;)Ljava/util/Properties;
		//   17: astore_3
		//   18: goto +16 -> 34
		//   21: getstatic 214	com/fedex/security/client/KeystoreCipherProviderImpl:propertiesCache	Ljava/util/Map;
		//   24: aload_1
		//   25: invokeinterface 194 2 0
		//   30: checkcast 215	java/util/Properties
		//   33: astore_3
		//   34: aload_3
		//   35: invokestatic 66	com/fedex/security/utils/SecurityUtils:trimProperties	(Ljava/util/Properties;)V
		//   38: aload_3
		//   39: ldc -40
		//   41: invokevirtual 36	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   44: invokestatic 217	java/security/KeyStore:getInstance	(Ljava/lang/String;)Ljava/security/KeyStore;
		//   47: astore 4
		//   49: aload_3
		//   50: ldc -38
		//   52: invokevirtual 36	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   55: invokestatic 219	com/fedex/security/common/FileLoader:getFileAsInputStream	(Ljava/lang/String;)Ljava/io/InputStream;
		//   58: astore_2
		//   59: aload 4
		//   61: aload_2
		//   62: aload_3
		//   63: ldc -36
		//   65: invokevirtual 36	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   68: invokevirtual 221	java/lang/String:toCharArray	()[C
		//   71: invokevirtual 222	java/security/KeyStore:load	(Ljava/io/InputStream;[C)V
		//   74: new 223	java/security/KeyStore$PasswordProtection
		//   77: dup
		//   78: aload_3
		//   79: ldc -32
		//   81: invokevirtual 36	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   84: invokevirtual 221	java/lang/String:toCharArray	()[C
		//   87: invokespecial 225	java/security/KeyStore$PasswordProtection:<init>	([C)V
		//   90: astore 5
		//   92: aload 4
		//   94: aload_3
		//   95: ldc -30
		//   97: invokevirtual 36	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   100: aload 5
		//   102: invokevirtual 227	java/security/KeyStore:getEntry	(Ljava/lang/String;Ljava/security/KeyStore$ProtectionParameter;)Ljava/security/KeyStore$Entry;
		//   105: checkcast 228	java/security/KeyStore$PrivateKeyEntry
		//   108: astore 6
		//   110: aload 6
		//   112: invokevirtual 229	java/security/KeyStore$PrivateKeyEntry:getCertificate	()Ljava/security/cert/Certificate;
		//   115: invokevirtual 230	java/security/cert/Certificate:getEncoded	()[B
		//   118: invokestatic 231	javax/security/cert/X509Certificate:getInstance	([B)Ljavax/security/cert/X509Certificate;
		//   121: invokevirtual 232	javax/security/cert/X509Certificate:getNotAfter	()Ljava/util/Date;
		//   124: new 180	java/util/Date
		//   127: dup
		//   128: invokespecial 181	java/util/Date:<init>	()V
		//   131: invokevirtual 182	java/util/Date:after	(Ljava/util/Date;)Z
		//   134: ifne +46 -> 180
		//   137: new 16	java/lang/StringBuilder
		//   140: dup
		//   141: invokespecial 17	java/lang/StringBuilder:<init>	()V
		//   144: ldc -72
		//   146: invokevirtual 19	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   149: aload_1
		//   150: invokevirtual 19	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   153: ldc -71
		//   155: invokevirtual 19	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   158: invokevirtual 21	java/lang/StringBuilder:toString	()Ljava/lang/String;
		//   161: astore 7
		//   163: getstatic 3	com/fedex/security/client/PkcTokenGeneratorImpl:logger	Lcom/fedex/framework/logging/FedExLoggerInterface;
		//   166: new 32	com/fedex/framework/logging/FedExLogEntry
		//   169: dup
		//   170: aload 7
		//   172: invokespecial 33	com/fedex/framework/logging/FedExLogEntry:<init>	(Ljava/lang/String;)V
		//   175: invokeinterface 34 2 0
		//   180: aload 6
		//   182: invokevirtual 229	java/security/KeyStore$PrivateKeyEntry:getCertificate	()Ljava/security/cert/Certificate;
		//   185: invokevirtual 230	java/security/cert/Certificate:getEncoded	()[B
		//   188: invokestatic 231	javax/security/cert/X509Certificate:getInstance	([B)Ljavax/security/cert/X509Certificate;
		//   191: invokevirtual 232	javax/security/cert/X509Certificate:getNotAfter	()Ljava/util/Date;
		//   194: astore 7
		//   196: aload_2
		//   197: ifnull +7 -> 204
		//   200: aload_2
		//   201: invokevirtual 233	java/io/InputStream:close	()V
		//   204: aload 7
		//   206: areturn
		//   207: astore 8
		//   209: aload_2
		//   210: ifnull +7 -> 217
		//   213: aload_2
		//   214: invokevirtual 233	java/io/InputStream:close	()V
		//   217: aload 8
		//   219: athrow
		//   220: astore_2
		//   221: new 16	java/lang/StringBuilder
		//   224: dup
		//   225: invokespecial 17	java/lang/StringBuilder:<init>	()V
		//   228: ldc -22
		//   230: invokevirtual 19	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   233: aload_1
		//   234: invokevirtual 19	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   237: invokevirtual 21	java/lang/StringBuilder:toString	()Ljava/lang/String;
		//   240: astore_3
		//   241: getstatic 3	com/fedex/security/client/PkcTokenGeneratorImpl:logger	Lcom/fedex/framework/logging/FedExLoggerInterface;
		//   244: new 32	com/fedex/framework/logging/FedExLogEntry
		//   247: dup
		//   248: aload_3
		//   249: invokespecial 33	com/fedex/framework/logging/FedExLogEntry:<init>	(Ljava/lang/String;)V
		//   252: aload_2
		//   253: invokeinterface 60 3 0
		//   258: new 14	java/lang/RuntimeException
		//   261: dup
		//   262: aload_3
		//   263: aload_2
		//   264: invokespecial 23	java/lang/RuntimeException:<init>	(Ljava/lang/String;Ljava/lang/Throwable;)V
		//   267: athrow
		// Line number table:
		//   Java source line #952	-> byte code offset #0
		//   Java source line #961	-> byte code offset #2
		//   Java source line #962	-> byte code offset #11
		//   Java source line #964	-> byte code offset #21
		//   Java source line #967	-> byte code offset #34
		//   Java source line #970	-> byte code offset #38
		//   Java source line #972	-> byte code offset #49
		//   Java source line #982	-> byte code offset #59
		//   Java source line #984	-> byte code offset #74
		//   Java source line #987	-> byte code offset #92
		//   Java source line #995	-> byte code offset #110
		//   Java source line #998	-> byte code offset #137
		//   Java source line #1000	-> byte code offset #163
		//   Java source line #1005	-> byte code offset #180
		//   Java source line #1008	-> byte code offset #196
		//   Java source line #1009	-> byte code offset #200
		//   Java source line #1008	-> byte code offset #207
		//   Java source line #1009	-> byte code offset #213
		//   Java source line #1012	-> byte code offset #220
		//   Java source line #1013	-> byte code offset #221
		//   Java source line #1015	-> byte code offset #241
		//   Java source line #1016	-> byte code offset #258
		// Local variable table:
		//   start	length	slot	name	signature
		//   0	268	0	this	PkcTokenGeneratorImpl
		//   0	268	1	clientId	String
		//   1	213	2	inputFile	java.io.InputStream
		//   220	44	2	e	Exception
		//   17	2	3	props	Properties
		//   33	62	3	props	Properties
		//   240	23	3	msg	String
		//   47	46	4	clientKeyStore	java.security.KeyStore
		//   90	11	5	keyPassword	java.security.KeyStore.PasswordProtection
		//   108	73	6	pkEntry	java.security.KeyStore.PrivateKeyEntry
		//   161	44	7	msg	String
		//   207	11	8	localObject	Object
		// Exception table:
		//   from	to	target	type
		//   2	196	207	finally
		//   207	209	207	finally
		//   0	204	220	java/lang/Exception
		//   207	220	220	java/lang/Exception
		return new Date();
	}

	public Date getCertExpiredDt(String fileName, String passphrase, String alias) {
		// Byte code:
		//   0: aconst_null
		//   1: astore 4
		//   3: ldc -21
		//   5: invokestatic 217	java/security/KeyStore:getInstance	(Ljava/lang/String;)Ljava/security/KeyStore;
		//   8: astore 5
		//   10: aload_1
		//   11: invokestatic 219	com/fedex/security/common/FileLoader:getFileAsInputStream	(Ljava/lang/String;)Ljava/io/InputStream;
		//   14: astore 4
		//   16: aload 5
		//   18: aload 4
		//   20: aload_2
		//   21: invokevirtual 221	java/lang/String:toCharArray	()[C
		//   24: invokevirtual 222	java/security/KeyStore:load	(Ljava/io/InputStream;[C)V
		//   27: new 223	java/security/KeyStore$PasswordProtection
		//   30: dup
		//   31: aload_2
		//   32: invokevirtual 221	java/lang/String:toCharArray	()[C
		//   35: invokespecial 225	java/security/KeyStore$PasswordProtection:<init>	([C)V
		//   38: astore 6
		//   40: aload 5
		//   42: aload_3
		//   43: aload 6
		//   45: invokevirtual 227	java/security/KeyStore:getEntry	(Ljava/lang/String;Ljava/security/KeyStore$ProtectionParameter;)Ljava/security/KeyStore$Entry;
		//   48: checkcast 228	java/security/KeyStore$PrivateKeyEntry
		//   51: astore 7
		//   53: aload 7
		//   55: invokevirtual 229	java/security/KeyStore$PrivateKeyEntry:getCertificate	()Ljava/security/cert/Certificate;
		//   58: invokevirtual 230	java/security/cert/Certificate:getEncoded	()[B
		//   61: invokestatic 231	javax/security/cert/X509Certificate:getInstance	([B)Ljavax/security/cert/X509Certificate;
		//   64: invokevirtual 232	javax/security/cert/X509Certificate:getNotAfter	()Ljava/util/Date;
		//   67: astore 8
		//   69: aload 4
		//   71: ifnull +8 -> 79
		//   74: aload 4
		//   76: invokevirtual 233	java/io/InputStream:close	()V
		//   79: aload 8
		//   81: areturn
		//   82: astore 9
		//   84: aload 4
		//   86: ifnull +8 -> 94
		//   89: aload 4
		//   91: invokevirtual 233	java/io/InputStream:close	()V
		//   94: aload 9
		//   96: athrow
		//   97: astore 4
		//   99: new 16	java/lang/StringBuilder
		//   102: dup
		//   103: invokespecial 17	java/lang/StringBuilder:<init>	()V
		//   106: ldc -22
		//   108: invokevirtual 19	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   111: aload_3
		//   112: invokevirtual 19	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   115: invokevirtual 21	java/lang/StringBuilder:toString	()Ljava/lang/String;
		//   118: astore 5
		//   120: aload 4
		//   122: invokevirtual 236	java/lang/Exception:printStackTrace	()V
		//   125: getstatic 3	com/fedex/security/client/PkcTokenGeneratorImpl:logger	Lcom/fedex/framework/logging/FedExLoggerInterface;
		//   128: new 32	com/fedex/framework/logging/FedExLogEntry
		//   131: dup
		//   132: aload 5
		//   134: invokespecial 33	com/fedex/framework/logging/FedExLogEntry:<init>	(Ljava/lang/String;)V
		//   137: aload 4
		//   139: invokeinterface 60 3 0
		//   144: new 14	java/lang/RuntimeException
		//   147: dup
		//   148: aload 5
		//   150: aload 4
		//   152: invokespecial 23	java/lang/RuntimeException:<init>	(Ljava/lang/String;Ljava/lang/Throwable;)V
		//   155: athrow
		// Line number table:
		//   Java source line #1025	-> byte code offset #0
		//   Java source line #1027	-> byte code offset #3
		//   Java source line #1028	-> byte code offset #10
		//   Java source line #1037	-> byte code offset #16
		//   Java source line #1039	-> byte code offset #27
		//   Java source line #1041	-> byte code offset #40
		//   Java source line #1044	-> byte code offset #53
		//   Java source line #1046	-> byte code offset #69
		//   Java source line #1047	-> byte code offset #74
		//   Java source line #1046	-> byte code offset #82
		//   Java source line #1047	-> byte code offset #89
		//   Java source line #1050	-> byte code offset #97
		//   Java source line #1051	-> byte code offset #99
		//   Java source line #1053	-> byte code offset #120
		//   Java source line #1054	-> byte code offset #125
		//   Java source line #1055	-> byte code offset #144
		// Local variable table:
		//   start	length	slot	name	signature
		//   0	156	0	this	PkcTokenGeneratorImpl
		//   0	156	1	fileName	String
		//   0	156	2	passphrase	String
		//   0	156	3	alias	String
		//   1	89	4	inputFile	java.io.InputStream
		//   97	54	4	e	Exception
		//   8	33	5	clientKeyStore	java.security.KeyStore
		//   118	31	5	msg	String
		//   38	6	6	keyPassword	java.security.KeyStore.PasswordProtection
		//   51	3	7	pkEntry	java.security.KeyStore.PrivateKeyEntry
		//   82	13	9	localObject	Object
		// Exception table:
		//   from	to	target	type
		//   3	69	82	finally
		//   82	84	82	finally
		//   0	79	97	java/lang/Exception
		//   82	97	97	java/lang/Exception
		return new Date();
	}

	public Date convertStringTimeToDate(String timeString) {
		Calendar date = Calendar.getInstance();
		DateFormat sdf = new SimpleDateFormat("HH:mm:ss");
		Date dateToBackup = null;
		try {
			dateToBackup = sdf.parse(timeString);
		}
		catch (ParseException e) {
			date.set(10, 6);
			date.set(12, 0);
			date.set(13, 0);
			date.set(14, 0);
			String msg = "Exception parsing the time string " + timeString + " provided in" + " security.properties, defaulting cert rotation time to 6:00AM GMT";
			logger.warn(new FedExLogEntry(msg), e);
			return date.getTime();
		}
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(dateToBackup);
		date.set(10, calendar.get(10));
		date.set(12, calendar.get(12));
		date.set(13, calendar.get(13));
		date.set(14, 0);
		return date.getTime();
	}

	private enum CertExprRange {
		DAYS_7,
		DAYS_14,
		DAYS_30,
		DAYS_40,
		GOOD;

		CertExprRange() {
		}

		public static CertExprRange getValue(float value) {
			CertExprRange returnValue = GOOD;
			if (value <= 40.0F) {
				if (value <= 7.0F) {
					returnValue = DAYS_7;
				}
				else {
					if (value <= 14.0F) {
						returnValue = DAYS_14;
					}
					else {
						if (value <= 30.0F) {
							returnValue = DAYS_30;
						}
						else {
							returnValue = DAYS_40;
						}
					}
				}
			}
			return returnValue;
		}
	}

	private static final class PkcTokenGeneratorImplHolder {
		private static PkcTokenGeneratorImpl instance = null;

		public static PkcTokenGeneratorImpl getInstance() {
			if (instance == null) {
				instance = new PkcTokenGeneratorImpl(null);
			}
			return instance;
		}

		public static PkcTokenGeneratorImpl getInstance(String propsFile) {
			if (instance == null) {
				instance = new PkcTokenGeneratorImpl(propsFile);
			}
			return instance;
		}
	}

	private final class TokenExpirationTask
			extends TimerTask {
		private TokenExpirationTask() {
		}

		public void run() {
			try {
				Map<String, Map<String, CachedItem>> localTokenCache = new HashMap();
				localTokenCache.putAll(PkcTokenGeneratorImpl.this.clientTokenCache);
				for (Iterator i$ = localTokenCache.keySet().iterator(); i$.hasNext(); ) {
					String clientId = (String)i$.next();
					Map<String, CachedItem> clientCache = localTokenCache.get(clientId);
					for (String serviceName : clientCache.keySet()) {
						CachedItem item = clientCache.get(serviceName);
						if (item.getCreateTime() < System.currentTimeMillis() - PkcTokenGeneratorImpl.this.tokenSafeTtlInSeconds * 1000L) {
							PkcTokenGeneratorImpl.this.encryptToken(clientId, serviceName, true);
						}
					}
				}
			}
			catch (Exception e) {
				String msg = "Token Expiration timer - Unable to rebuild token";
				PkcTokenGeneratorImpl.logger.error(new FedExLogEntry("Token Expiration timer - Unable to rebuild token"));
			}
//			PkcTokenGeneratorImpl(System.currentTimeMillis());
			PkcTokenGeneratorImpl.logger.trace(new FedExLogEntry("Token Expiration timer task running"));
			KeystoreExpirationCheck.handleFatalLogs(PkcTokenGeneratorImpl.getClientIdFromFingerPrint());
		}
	}

	private final class RotationCallbackImpl
			implements CipherProvider.RotationCallback {
		private RotationCallbackImpl() {
		}

		public final void cleanup(String clientId) {
			PkcTokenGeneratorImpl.this.clientTokenCache.remove(clientId);
		}
	}

	private final class CertRotationTimerTask
			extends TimerTask {
		private CertRotationTimerTask() {
		}

		public void run() {
			try {
				if (KeystoreExpirationCheck.rotationCheck(PkcTokenGeneratorImpl.getClientIdFromFingerPrint())) {
					ClientCipherProviderFactory.getProvider().getEncryptionCipher(PkcTokenGeneratorImpl.getClientIdFromFingerPrint(), true);
					PkcTokenGeneratorImpl
							tmp32_29 = PkcTokenGeneratorImpl.getInstance();
					tmp32_29.getClass();
					ClientCipherProviderFactory.getProvider().setRotationCallback(new PkcTokenGeneratorImpl.RotationCallbackImpl());
				}
			}
			catch (Exception e) {
				String msg = "Exception occured in cert rotation timer";
				PkcTokenGeneratorImpl.logger.error(new FedExLogEntry("Exception occured in cert rotation timer"), e);
			}
//			PkcTokenGeneratorImpl.access$1002(System.currentTimeMillis());
		}
	}
}
