package com.fedex.security.client;

import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import com.fedex.security.common.CipherProvider;
import com.fedex.security.common.FileLoader;
import com.fedex.security.exceptions.SecurityConfigurationException;

import javax.crypto.Cipher;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Timer;

public final class KeystoreCipherProviderImpl
		implements CipherProvider {
	public static final String CLIENT_KEYSTORE_TYPE = "client.keystore.type";
	public static final String CLIENT_KEYSTORE_FILE_PROP = "client.keystore.file";
	public static final String CLIENT_KEYSTORE_PASS_PROP = "client.keystore.password";
	public static final String CLIENT_KEYSTORE_KEY_ALIAS_PROP = "client.keystore.key.alias";
	public static final String CLIENT_PRIVATE_KEY_PASS_PROP = "client.private.key.password";
	public static final String CERT_ROTATION_CHECK_IN_SECONDS_PROP = "security.api.client.cert.rotation.check";
	public static final String CDS_URL = "cds.url";
	public static final String AUTOCERT_ROTATION_FLAG = "autocertrotation.flag";
	private static Timer rotationTimer = null;
	private Map<String, Properties> clientPropertiesCache;
	protected static Map<String, Properties> propertiesCache;
	protected static Date certExprDate = null;
	private Map<String, Cipher> clientCipherCache;
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(KeystoreCipherProviderImpl.class.getName());
	private static CipherProvider.RotationCallback rotationCallback = null;
	protected static String absolutePathOfClientFile = "";
	protected static String absolutePathOfCert = "";
	private String cdsUrl = null;
	private boolean autoCertRotation = false;

	private KeystoreCipherProviderImpl() {
		this("security.properties");
	}

	private KeystoreCipherProviderImpl(String pathWithPropsFileName) {
		Properties props = null;
		try {
			props = FileLoader.getFileAsProperties(pathWithPropsFileName);
		}
		catch (RuntimeException re) {
			FileLoader.alwaysLogFiles(pathWithPropsFileName);
			String msg = "Could not load the securityProperties file '" + pathWithPropsFileName + "'.  Please verify the file exists at the absolute location or in the classpath.";
			logger.fatal(msg);
			throw new RuntimeException(msg, re);
		}
		if (!props.containsKey("security.api.client.cert.rotation.check")) {
			FileLoader.alwaysLogFiles(pathWithPropsFileName);
			String msg = "The property security.api.client.cert.rotation.check is missing in the '" + pathWithPropsFileName + "' file. Verify content of securityProperties.";
			logger.fatal(new FedExLogEntry(msg));
			throw new RuntimeException(msg);
		}
		try {
			logger.info(new FedExLogEntry("KeystoreCipherProviderImpl instance created"));
			this.clientPropertiesCache = Collections.synchronizedMap(new HashMap());
			propertiesCache = Collections.synchronizedMap(new HashMap());
			this.clientCipherCache = Collections.synchronizedMap(new HashMap());
			logger.info(new FedExLogEntry("Caches initialized"));
		}
		catch (NumberFormatException nfe) {
			FileLoader.alwaysLogFiles(pathWithPropsFileName);
			String msg = "The property 'security.api.client.cert.rotation.check' has an invalid number of '" + props.getProperty("security.api.client.cert.rotation.check") + "' in the securityProperties file '" + pathWithPropsFileName + "'";
			logger.fatal(msg);
			throw new RuntimeException(msg, nfe);
		}
		catch (Exception e) {
			String msg = "Failed to configure CipherProvider due to invalid values provided for properties, exiting. Verify content of security properties";
			logger.fatal(new FedExLogEntry("Failed to configure CipherProvider due to invalid values provided for properties, exiting. Verify content of security properties"));
			throw new RuntimeException("Failed to configure CipherProvider due to invalid values provided for properties, exiting. Verify content of security properties", e);
		}
		try {
			this.cdsUrl = props.getProperty("cds.url");
			if (!"false".equalsIgnoreCase(props.getProperty("autocertrotation.flag"))) {
				this.autoCertRotation = true;
			}
			else {
				this.autoCertRotation = false;
				if (!"true".equalsIgnoreCase(props.getProperty("autocertrotation.flag"))) {
					String msg = "autocertrotation.flag is not empty or set to 'true' or 'false' in the property file, defaulting to true.";
					logger.warn(new FedExLogEntry(msg));
				}
			}
		}
		catch (Exception e) {
			String msg = "Failed to aquire certificate rotation information from the properties file";
			logger.fatal(new FedExLogEntry("Failed to aquire certificate rotation information from the properties file"));
			throw new RuntimeException("Failed to aquire certificate rotation information from the properties file", e);
		}
	}

	private static final class KeystoreCipherProviderImplHolder {
		private static KeystoreCipherProviderImpl instance = null;

		public static KeystoreCipherProviderImpl getInstance() {
			if (instance == null) {
				instance = new KeystoreCipherProviderImpl(null);
			}
			return instance;
		}

		public static KeystoreCipherProviderImpl getInstance(String propsFile) {
			if (instance == null) {
				instance = new KeystoreCipherProviderImpl(propsFile);
			}
			return instance;
		}
	}

	public static final KeystoreCipherProviderImpl getInstance() {
		return KeystoreCipherProviderImplHolder.getInstance();
	}

	public final void configure(String clientId, Properties props, boolean forceReconfigure) {
		if (forceReconfigure) {
			if (this.clientPropertiesCache.containsKey(clientId)) {
				if (canConfigure(clientId, props) == true) {
					this.clientPropertiesCache.remove(clientId);
					configure(clientId, props);
				}
			}
		}
	}

	public final void configure(String clientId, Properties props) {
		if (canConfigure(clientId, props) == true) {
			if (!this.clientPropertiesCache.containsKey(clientId)) {
				this.clientPropertiesCache.put(clientId, props);
				certExprDate = getCertExprDt(clientId, props);
				propertiesCache.put(clientId, props);
				logger.info(new FedExLogEntry("KeystoreCipherProviderImpl configured for use with client " + clientId));
				getEncryptionCipher(clientId);
			}
			else {
				logger.info(new FedExLogEntry("KeystoreCipherProviderImpl already configured for client " + clientId + ", ignoring"));
			}
		}
	}

	public final boolean canConfigure(String clientId, Properties props) {
		StringBuilder errorMessage = new StringBuilder();
		if ("APP".equalsIgnoreCase(clientId)) {
			errorMessage.append("Application ID is missing from fp.properties file.  ");
		}
		if (!props.containsKey("client.keystore.type")) {
			errorMessage.append("The clientProperties file does not contain the required 'client.keystore.type' property.  ");
		}
		if (!props.containsKey("client.keystore.file")) {
			errorMessage.append("The clientProperties file does not contain the required 'client.keystore.file' property.  ");
		}
		if (!props.containsKey("client.keystore.password")) {
			errorMessage.append("The clientProperties file does not contain the required 'client.keystore.password' property.  ");
		}
		if (!props.containsKey("client.keystore.key.alias")) {
			errorMessage.append("The clientProperties file does not contain the required 'client.keystore.key.alias' property.  ");
		}
		if (!props.containsKey("client.private.key.password")) {
			errorMessage.append("The clientProperties file does not contain the required 'client.private.key.password' property.  ");
		}
		if (errorMessage.length() != 0) {
			String msg = errorMessage.toString();
			logger.fatal(msg);
			throw new SecurityConfigurationException(msg);
		}
		props.put("client.keystore.password", props.get("client.keystore.password").toString().trim());
		props.put("client.private.key.password", props.get("client.private.key.password").toString().trim());
		return true;
	}

	public static final KeystoreCipherProviderImpl getInstance(String propsFile) {
		return KeystoreCipherProviderImplHolder.getInstance(propsFile);
	}

	public final boolean isConfigured(String clientId) {
		return getInstance().clientPropertiesCache.containsKey(clientId);
	}

	public Cipher getEncryptionCipher(String clientId) {
		return getEncryptionCipher(clientId, false);
	}

	public Cipher getEncryptionCipher(String clientId, boolean ignoreCache) {
		if ((!ignoreCache) && (this.clientCipherCache.containsKey(clientId))) {
			logger.trace(new FedExLogEntry("Cached cipher returned for client " + clientId));
			return this.clientCipherCache.get(clientId);
		}
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(1, getPrivateKey(clientId));
			this.clientCipherCache.put(clientId, cipher);
			logger.trace(new FedExLogEntry("Cipher cached for client " + clientId));
			return cipher;
		}
		catch (Exception e) {
			String msg = "Exception generating cipher for client. Keystore file (.p12) file is missing or passphrase is incorrect. Client= " + clientId;
			logger.fatal(new FedExLogEntry(msg), e);
			throw new RuntimeException(msg, e);
		}
	}

	private final java.security.PrivateKey getPrivateKey(String clientId)
			throws SecurityConfigurationException {
		// Byte code:
		//   0: aconst_null
		//   1: astore_2
		//   2: aconst_null
		//   3: astore_3
		//   4: getstatic 96	com/fedex/security/client/KeystoreCipherProviderImpl:absolutePathOfClientFile	Ljava/lang/String;
		//   7: invokestatic 97	com/fedex/security/common/StringUtils:isNullOrBlank	(Ljava/lang/String;)Z
		//   10: ifne +13 -> 23
		//   13: getstatic 96	com/fedex/security/client/KeystoreCipherProviderImpl:absolutePathOfClientFile	Ljava/lang/String;
		//   16: invokestatic 7	com/fedex/security/common/FileLoader:getFileAsProperties	(Ljava/lang/String;)Ljava/util/Properties;
		//   19: astore_3
		//   20: goto +17 -> 37
		//   23: aload_0
		//   24: getfield 32	com/fedex/security/client/KeystoreCipherProviderImpl:clientPropertiesCache	Ljava/util/Map;
		//   27: aload_1
		//   28: invokeinterface 87 2 0
		//   33: checkcast 98	java/util/Properties
		//   36: astore_3
		//   37: aload_3
		//   38: invokestatic 99	com/fedex/security/utils/SecurityUtils:trimProperties	(Ljava/util/Properties;)V
		//   41: aload_3
		//   42: ldc 65
		//   44: invokevirtual 38	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   47: invokestatic 100	java/security/KeyStore:getInstance	(Ljava/lang/String;)Ljava/security/KeyStore;
		//   50: astore 4
		//   52: aload_3
		//   53: ldc 67
		//   55: invokevirtual 38	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   58: invokestatic 101	com/fedex/security/common/FileLoader:getFileAsInputStream	(Ljava/lang/String;)Ljava/io/InputStream;
		//   61: astore_2
		//   62: aload_2
		//   63: ifnonnull +56 -> 119
		//   66: new 10	java/lang/StringBuilder
		//   69: dup
		//   70: invokespecial 11	java/lang/StringBuilder:<init>	()V
		//   73: ldc 102
		//   75: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   78: aload_1
		//   79: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   82: ldc 103
		//   84: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   87: invokevirtual 15	java/lang/StringBuilder:toString	()Ljava/lang/String;
		//   90: astore 5
		//   92: getstatic 16	com/fedex/security/client/KeystoreCipherProviderImpl:logger	Lcom/fedex/framework/logging/FedExLoggerInterface;
		//   95: new 23	com/fedex/framework/logging/FedExLogEntry
		//   98: dup
		//   99: aload 5
		//   101: invokespecial 24	com/fedex/framework/logging/FedExLogEntry:<init>	(Ljava/lang/String;)V
		//   104: invokeinterface 25 2 0
		//   109: new 76	com/fedex/security/exceptions/SecurityConfigurationException
		//   112: dup
		//   113: aload 5
		//   115: invokespecial 77	com/fedex/security/exceptions/SecurityConfigurationException:<init>	(Ljava/lang/String;)V
		//   118: athrow
		//   119: aload 4
		//   121: aload_2
		//   122: aload_3
		//   123: ldc 69
		//   125: invokevirtual 38	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   128: invokevirtual 104	java/lang/String:toCharArray	()[C
		//   131: invokevirtual 105	java/security/KeyStore:load	(Ljava/io/InputStream;[C)V
		//   134: new 106	java/security/KeyStore$PasswordProtection
		//   137: dup
		//   138: aload_3
		//   139: ldc 73
		//   141: invokevirtual 38	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   144: invokevirtual 104	java/lang/String:toCharArray	()[C
		//   147: invokespecial 107	java/security/KeyStore$PasswordProtection:<init>	([C)V
		//   150: astore 5
		//   152: aload 4
		//   154: aload_3
		//   155: ldc 71
		//   157: invokevirtual 38	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   160: aload 5
		//   162: invokevirtual 108	java/security/KeyStore:getEntry	(Ljava/lang/String;Ljava/security/KeyStore$ProtectionParameter;)Ljava/security/KeyStore$Entry;
		//   165: checkcast 109	java/security/KeyStore$PrivateKeyEntry
		//   168: astore 6
		//   170: aload 6
		//   172: invokevirtual 110	java/security/KeyStore$PrivateKeyEntry:getCertificate	()Ljava/security/cert/Certificate;
		//   175: invokevirtual 111	java/security/cert/Certificate:getEncoded	()[B
		//   178: invokestatic 112	javax/security/cert/X509Certificate:getInstance	([B)Ljavax/security/cert/X509Certificate;
		//   181: invokevirtual 113	javax/security/cert/X509Certificate:getNotAfter	()Ljava/util/Date;
		//   184: new 114	java/util/Date
		//   187: dup
		//   188: invokespecial 115	java/util/Date:<init>	()V
		//   191: invokevirtual 116	java/util/Date:after	(Ljava/util/Date;)Z
		//   194: ifne +56 -> 250
		//   197: new 10	java/lang/StringBuilder
		//   200: dup
		//   201: invokespecial 11	java/lang/StringBuilder:<init>	()V
		//   204: ldc 117
		//   206: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   209: aload_1
		//   210: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   213: ldc 118
		//   215: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   218: invokevirtual 15	java/lang/StringBuilder:toString	()Ljava/lang/String;
		//   221: astore 7
		//   223: getstatic 16	com/fedex/security/client/KeystoreCipherProviderImpl:logger	Lcom/fedex/framework/logging/FedExLoggerInterface;
		//   226: new 23	com/fedex/framework/logging/FedExLogEntry
		//   229: dup
		//   230: aload 7
		//   232: invokespecial 24	com/fedex/framework/logging/FedExLogEntry:<init>	(Ljava/lang/String;)V
		//   235: invokeinterface 25 2 0
		//   240: new 76	com/fedex/security/exceptions/SecurityConfigurationException
		//   243: dup
		//   244: aload 7
		//   246: invokespecial 77	com/fedex/security/exceptions/SecurityConfigurationException:<init>	(Ljava/lang/String;)V
		//   249: athrow
		//   250: aload 6
		//   252: invokevirtual 119	java/security/KeyStore$PrivateKeyEntry:getPrivateKey	()Ljava/security/PrivateKey;
		//   255: astore 7
		//   257: aload_2
		//   258: ifnull +7 -> 265
		//   261: aload_2
		//   262: invokevirtual 120	java/io/InputStream:close	()V
		//   265: aload 7
		//   267: areturn
		//   268: astore 8
		//   270: aload_2
		//   271: ifnull +7 -> 278
		//   274: aload_2
		//   275: invokevirtual 120	java/io/InputStream:close	()V
		//   278: aload 8
		//   280: athrow
		//   281: astore_2
		//   282: new 10	java/lang/StringBuilder
		//   285: dup
		//   286: invokespecial 11	java/lang/StringBuilder:<init>	()V
		//   289: ldc 121
		//   291: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   294: aload_1
		//   295: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   298: invokevirtual 15	java/lang/StringBuilder:toString	()Ljava/lang/String;
		//   301: astore_3
		//   302: getstatic 16	com/fedex/security/client/KeystoreCipherProviderImpl:logger	Lcom/fedex/framework/logging/FedExLoggerInterface;
		//   305: new 23	com/fedex/framework/logging/FedExLogEntry
		//   308: dup
		//   309: aload_3
		//   310: invokespecial 24	com/fedex/framework/logging/FedExLogEntry:<init>	(Ljava/lang/String;)V
		//   313: aload_2
		//   314: invokeinterface 95 3 0
		//   319: new 8	java/lang/RuntimeException
		//   322: dup
		//   323: aload_3
		//   324: aload_2
		//   325: invokespecial 18	java/lang/RuntimeException:<init>	(Ljava/lang/String;Ljava/lang/Throwable;)V
		//   328: athrow
		// Line number table:
		//   Java source line #358	-> byte code offset #0
		//   Java source line #361	-> byte code offset #2
		//   Java source line #363	-> byte code offset #4
		//   Java source line #364	-> byte code offset #13
		//   Java source line #366	-> byte code offset #23
		//   Java source line #369	-> byte code offset #37
		//   Java source line #378	-> byte code offset #41
		//   Java source line #379	-> byte code offset #52
		//   Java source line #380	-> byte code offset #62
		//   Java source line #382	-> byte code offset #66
		//   Java source line #383	-> byte code offset #92
		//   Java source line #384	-> byte code offset #109
		//   Java source line #387	-> byte code offset #119
		//   Java source line #388	-> byte code offset #134
		//   Java source line #389	-> byte code offset #152
		//   Java source line #392	-> byte code offset #170
		//   Java source line #394	-> byte code offset #197
		//   Java source line #395	-> byte code offset #223
		//   Java source line #396	-> byte code offset #240
		//   Java source line #399	-> byte code offset #250
		//   Java source line #403	-> byte code offset #257
		//   Java source line #405	-> byte code offset #261
		//   Java source line #403	-> byte code offset #268
		//   Java source line #405	-> byte code offset #274
		//   Java source line #409	-> byte code offset #281
		//   Java source line #411	-> byte code offset #282
		//   Java source line #412	-> byte code offset #302
		//   Java source line #413	-> byte code offset #319
		// Local variable table:
		//   start	length	slot	name	signature
		//   0	329	0	this	KeystoreCipherProviderImpl
		//   0	329	1	clientId	String
		//   1	274	2	inputFile	java.io.InputStream
		//   281	44	2	e	Exception
		//   3	152	3	props	Properties
		//   301	23	3	msg	String
		//   50	103	4	clientKeyStore	java.security.KeyStore
		//   90	24	5	msg	String
		//   150	11	5	keyPassword	java.security.KeyStore.PasswordProtection
		//   168	83	6	pkEntry	java.security.KeyStore.PrivateKeyEntry
		//   221	45	7	msg	String
		//   268	11	8	localObject	Object
		// Exception table:
		//   from	to	target	type
		//   2	257	268	finally
		//   268	270	268	finally
		//   0	265	281	java/lang/Exception
		//   268	281	281	java/lang/Exception
		try {
			byte[] keyBytes = Files.readAllBytes(Paths.get(absolutePathOfClientFile));

			PKCS8EncodedKeySpec spec =
					new PKCS8EncodedKeySpec(keyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePrivate(spec);
		}
		catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
			logger.error("Exception Caught", e);
		}
		return null;
	}

	public void setRotationCallback(CipherProvider.RotationCallback callback) {
		rotationCallback = callback;
	}

	public Cipher[] getDecryptionCiphers(String clientId) {
		return null;
	}

	public Cipher[] getDecryptionCiphers(String clientId, boolean ignoreCache) {
		return null;
	}

	public void resetDecryptionCipher(String clientId, Cipher cipher) {
	}

	private Date getCertExprDt(String clientId, Properties props) {
		// Byte code:
		//   0: aconst_null
		//   1: astore_3
		//   2: aload_2
		//   3: ifnonnull +3 -> 6
		//   6: aload_2
		//   7: ldc 65
		//   9: invokevirtual 38	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   12: invokestatic 100	java/security/KeyStore:getInstance	(Ljava/lang/String;)Ljava/security/KeyStore;
		//   15: astore 4
		//   17: aload_2
		//   18: ldc 67
		//   20: invokevirtual 38	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   23: invokestatic 101	com/fedex/security/common/FileLoader:getFileAsInputStream	(Ljava/lang/String;)Ljava/io/InputStream;
		//   26: astore_3
		//   27: goto +67 -> 94
		//   30: astore 5
		//   32: aload_2
		//   33: ldc 67
		//   35: invokevirtual 38	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   38: invokestatic 9	com/fedex/security/common/FileLoader:alwaysLogFiles	(Ljava/lang/String;)V
		//   41: new 10	java/lang/StringBuilder
		//   44: dup
		//   45: invokespecial 11	java/lang/StringBuilder:<init>	()V
		//   48: ldc 123
		//   50: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   53: aload_2
		//   54: ldc 67
		//   56: invokevirtual 38	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   59: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   62: ldc 14
		//   64: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   67: invokevirtual 15	java/lang/StringBuilder:toString	()Ljava/lang/String;
		//   70: astore 6
		//   72: getstatic 16	com/fedex/security/client/KeystoreCipherProviderImpl:logger	Lcom/fedex/framework/logging/FedExLoggerInterface;
		//   75: aload 6
		//   77: invokeinterface 17 2 0
		//   82: new 76	com/fedex/security/exceptions/SecurityConfigurationException
		//   85: dup
		//   86: aload 6
		//   88: aload 5
		//   90: invokespecial 124	com/fedex/security/exceptions/SecurityConfigurationException:<init>	(Ljava/lang/String;Ljava/lang/Throwable;)V
		//   93: athrow
		//   94: aload_3
		//   95: ifnonnull +63 -> 158
		//   98: aload_2
		//   99: ldc 67
		//   101: invokevirtual 38	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   104: invokestatic 9	com/fedex/security/common/FileLoader:alwaysLogFiles	(Ljava/lang/String;)V
		//   107: new 10	java/lang/StringBuilder
		//   110: dup
		//   111: invokespecial 11	java/lang/StringBuilder:<init>	()V
		//   114: ldc 123
		//   116: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   119: aload_2
		//   120: ldc 67
		//   122: invokevirtual 38	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   125: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   128: ldc 14
		//   130: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   133: invokevirtual 15	java/lang/StringBuilder:toString	()Ljava/lang/String;
		//   136: astore 5
		//   138: getstatic 16	com/fedex/security/client/KeystoreCipherProviderImpl:logger	Lcom/fedex/framework/logging/FedExLoggerInterface;
		//   141: aload 5
		//   143: invokeinterface 17 2 0
		//   148: new 76	com/fedex/security/exceptions/SecurityConfigurationException
		//   151: dup
		//   152: aload 5
		//   154: invokespecial 77	com/fedex/security/exceptions/SecurityConfigurationException:<init>	(Ljava/lang/String;)V
		//   157: athrow
		//   158: aload 4
		//   160: aload_3
		//   161: aload_2
		//   162: ldc 69
		//   164: invokevirtual 38	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   167: invokevirtual 104	java/lang/String:toCharArray	()[C
		//   170: invokevirtual 105	java/security/KeyStore:load	(Ljava/io/InputStream;[C)V
		//   173: goto +77 -> 250
		//   176: astore 5
		//   178: aload_2
		//   179: ldc 67
		//   181: invokevirtual 38	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   184: invokestatic 9	com/fedex/security/common/FileLoader:alwaysLogFiles	(Ljava/lang/String;)V
		//   187: new 10	java/lang/StringBuilder
		//   190: dup
		//   191: invokespecial 11	java/lang/StringBuilder:<init>	()V
		//   194: ldc 123
		//   196: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   199: aload_2
		//   200: ldc 67
		//   202: invokevirtual 38	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   205: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   208: ldc 126
		//   210: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   213: ldc 69
		//   215: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   218: ldc 127
		//   220: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   223: invokevirtual 15	java/lang/StringBuilder:toString	()Ljava/lang/String;
		//   226: astore 6
		//   228: getstatic 16	com/fedex/security/client/KeystoreCipherProviderImpl:logger	Lcom/fedex/framework/logging/FedExLoggerInterface;
		//   231: aload 6
		//   233: invokeinterface 17 2 0
		//   238: new 76	com/fedex/security/exceptions/SecurityConfigurationException
		//   241: dup
		//   242: aload 6
		//   244: aload 5
		//   246: invokespecial 124	com/fedex/security/exceptions/SecurityConfigurationException:<init>	(Ljava/lang/String;Ljava/lang/Throwable;)V
		//   249: athrow
		//   250: new 106	java/security/KeyStore$PasswordProtection
		//   253: dup
		//   254: aload_2
		//   255: ldc 73
		//   257: invokevirtual 38	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   260: invokevirtual 104	java/lang/String:toCharArray	()[C
		//   263: invokespecial 107	java/security/KeyStore$PasswordProtection:<init>	([C)V
		//   266: astore 5
		//   268: aload 4
		//   270: aload_2
		//   271: ldc 71
		//   273: invokevirtual 38	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   276: aload 5
		//   278: invokevirtual 108	java/security/KeyStore:getEntry	(Ljava/lang/String;Ljava/security/KeyStore$ProtectionParameter;)Ljava/security/KeyStore$Entry;
		//   281: checkcast 109	java/security/KeyStore$PrivateKeyEntry
		//   284: astore 6
		//   286: aload 6
		//   288: ifnonnull +80 -> 368
		//   291: aload_2
		//   292: ldc 67
		//   294: invokevirtual 38	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   297: invokestatic 9	com/fedex/security/common/FileLoader:alwaysLogFiles	(Ljava/lang/String;)V
		//   300: new 10	java/lang/StringBuilder
		//   303: dup
		//   304: invokespecial 11	java/lang/StringBuilder:<init>	()V
		//   307: ldc -128
		//   309: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   312: aload_2
		//   313: ldc 67
		//   315: invokevirtual 38	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   318: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   321: ldc -127
		//   323: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   326: ldc 71
		//   328: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   331: ldc -126
		//   333: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   336: invokevirtual 15	java/lang/StringBuilder:toString	()Ljava/lang/String;
		//   339: astore 7
		//   341: getstatic 16	com/fedex/security/client/KeystoreCipherProviderImpl:logger	Lcom/fedex/framework/logging/FedExLoggerInterface;
		//   344: new 23	com/fedex/framework/logging/FedExLogEntry
		//   347: dup
		//   348: aload 7
		//   350: invokespecial 24	com/fedex/framework/logging/FedExLogEntry:<init>	(Ljava/lang/String;)V
		//   353: invokeinterface 25 2 0
		//   358: new 76	com/fedex/security/exceptions/SecurityConfigurationException
		//   361: dup
		//   362: aload 7
		//   364: invokespecial 77	com/fedex/security/exceptions/SecurityConfigurationException:<init>	(Ljava/lang/String;)V
		//   367: athrow
		//   368: aload 6
		//   370: invokevirtual 110	java/security/KeyStore$PrivateKeyEntry:getCertificate	()Ljava/security/cert/Certificate;
		//   373: invokevirtual 111	java/security/cert/Certificate:getEncoded	()[B
		//   376: invokestatic 112	javax/security/cert/X509Certificate:getInstance	([B)Ljavax/security/cert/X509Certificate;
		//   379: invokevirtual 113	javax/security/cert/X509Certificate:getNotAfter	()Ljava/util/Date;
		//   382: astore 7
		//   384: aload_3
		//   385: ifnull +7 -> 392
		//   388: aload_3
		//   389: invokevirtual 120	java/io/InputStream:close	()V
		//   392: aload 7
		//   394: areturn
		//   395: astore 8
		//   397: aload_3
		//   398: ifnull +7 -> 405
		//   401: aload_3
		//   402: invokevirtual 120	java/io/InputStream:close	()V
		//   405: aload 8
		//   407: athrow
		//   408: astore_3
		//   409: new 10	java/lang/StringBuilder
		//   412: dup
		//   413: invokespecial 11	java/lang/StringBuilder:<init>	()V
		//   416: ldc -124
		//   418: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   421: aload_2
		//   422: ldc 65
		//   424: invokevirtual 38	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   427: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   430: ldc -123
		//   432: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   435: ldc 65
		//   437: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   440: ldc -122
		//   442: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   445: invokevirtual 15	java/lang/StringBuilder:toString	()Ljava/lang/String;
		//   448: astore 4
		//   450: getstatic 16	com/fedex/security/client/KeystoreCipherProviderImpl:logger	Lcom/fedex/framework/logging/FedExLoggerInterface;
		//   453: new 23	com/fedex/framework/logging/FedExLogEntry
		//   456: dup
		//   457: aload 4
		//   459: invokespecial 24	com/fedex/framework/logging/FedExLogEntry:<init>	(Ljava/lang/String;)V
		//   462: aload_3
		//   463: invokeinterface 95 3 0
		//   468: new 8	java/lang/RuntimeException
		//   471: dup
		//   472: aload 4
		//   474: aload_3
		//   475: invokespecial 18	java/lang/RuntimeException:<init>	(Ljava/lang/String;Ljava/lang/Throwable;)V
		//   478: athrow
		//   479: astore_3
		//   480: aload_2
		//   481: ldc 67
		//   483: invokevirtual 38	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   486: invokestatic 9	com/fedex/security/common/FileLoader:alwaysLogFiles	(Ljava/lang/String;)V
		//   489: new 10	java/lang/StringBuilder
		//   492: dup
		//   493: invokespecial 11	java/lang/StringBuilder:<init>	()V
		//   496: ldc -128
		//   498: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   501: aload_2
		//   502: ldc 67
		//   504: invokevirtual 38	java/util/Properties:getProperty	(Ljava/lang/String;)Ljava/lang/String;
		//   507: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   510: ldc -127
		//   512: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   515: ldc 73
		//   517: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   520: ldc -120
		//   522: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   525: ldc 69
		//   527: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   530: ldc -119
		//   532: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   535: invokevirtual 15	java/lang/StringBuilder:toString	()Ljava/lang/String;
		//   538: astore 4
		//   540: getstatic 16	com/fedex/security/client/KeystoreCipherProviderImpl:logger	Lcom/fedex/framework/logging/FedExLoggerInterface;
		//   543: new 23	com/fedex/framework/logging/FedExLogEntry
		//   546: dup
		//   547: aload 4
		//   549: invokespecial 24	com/fedex/framework/logging/FedExLogEntry:<init>	(Ljava/lang/String;)V
		//   552: invokeinterface 25 2 0
		//   557: new 76	com/fedex/security/exceptions/SecurityConfigurationException
		//   560: dup
		//   561: aload 4
		//   563: aload_3
		//   564: invokespecial 124	com/fedex/security/exceptions/SecurityConfigurationException:<init>	(Ljava/lang/String;Ljava/lang/Throwable;)V
		//   567: athrow
		//   568: astore_3
		//   569: aload_3
		//   570: athrow
		//   571: astore_3
		//   572: new 10	java/lang/StringBuilder
		//   575: dup
		//   576: invokespecial 11	java/lang/StringBuilder:<init>	()V
		//   579: ldc 121
		//   581: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   584: aload_1
		//   585: invokevirtual 13	java/lang/StringBuilder:append	(Ljava/lang/String;)Ljava/lang/StringBuilder;
		//   588: invokevirtual 15	java/lang/StringBuilder:toString	()Ljava/lang/String;
		//   591: astore 4
		//   593: getstatic 16	com/fedex/security/client/KeystoreCipherProviderImpl:logger	Lcom/fedex/framework/logging/FedExLoggerInterface;
		//   596: new 23	com/fedex/framework/logging/FedExLogEntry
		//   599: dup
		//   600: aload 4
		//   602: invokespecial 24	com/fedex/framework/logging/FedExLogEntry:<init>	(Ljava/lang/String;)V
		//   605: aload_3
		//   606: invokeinterface 95 3 0
		//   611: new 8	java/lang/RuntimeException
		//   614: dup
		//   615: aload 4
		//   617: aload_3
		//   618: invokespecial 18	java/lang/RuntimeException:<init>	(Ljava/lang/String;Ljava/lang/Throwable;)V
		//   621: athrow
		// Line number table:
		//   Java source line #446	-> byte code offset #0
		//   Java source line #449	-> byte code offset #2
		//   Java source line #453	-> byte code offset #6
		//   Java source line #456	-> byte code offset #17
		//   Java source line #462	-> byte code offset #27
		//   Java source line #457	-> byte code offset #30
		//   Java source line #458	-> byte code offset #32
		//   Java source line #459	-> byte code offset #41
		//   Java source line #460	-> byte code offset #72
		//   Java source line #461	-> byte code offset #82
		//   Java source line #469	-> byte code offset #94
		//   Java source line #471	-> byte code offset #98
		//   Java source line #472	-> byte code offset #107
		//   Java source line #473	-> byte code offset #138
		//   Java source line #474	-> byte code offset #148
		//   Java source line #478	-> byte code offset #158
		//   Java source line #485	-> byte code offset #173
		//   Java source line #479	-> byte code offset #176
		//   Java source line #480	-> byte code offset #178
		//   Java source line #481	-> byte code offset #187
		//   Java source line #482	-> byte code offset #228
		//   Java source line #483	-> byte code offset #238
		//   Java source line #486	-> byte code offset #250
		//   Java source line #487	-> byte code offset #268
		//   Java source line #488	-> byte code offset #286
		//   Java source line #489	-> byte code offset #291
		//   Java source line #490	-> byte code offset #300
		//   Java source line #491	-> byte code offset #341
		//   Java source line #492	-> byte code offset #358
		//   Java source line #494	-> byte code offset #368
		//   Java source line #498	-> byte code offset #384
		//   Java source line #500	-> byte code offset #388
		//   Java source line #498	-> byte code offset #395
		//   Java source line #500	-> byte code offset #401
		//   Java source line #503	-> byte code offset #408
		//   Java source line #504	-> byte code offset #409
		//   Java source line #505	-> byte code offset #450
		//   Java source line #506	-> byte code offset #468
		//   Java source line #507	-> byte code offset #479
		//   Java source line #508	-> byte code offset #480
		//   Java source line #509	-> byte code offset #489
		//   Java source line #510	-> byte code offset #540
		//   Java source line #511	-> byte code offset #557
		//   Java source line #512	-> byte code offset #568
		//   Java source line #513	-> byte code offset #569
		//   Java source line #514	-> byte code offset #571
		//   Java source line #516	-> byte code offset #572
		//   Java source line #517	-> byte code offset #593
		//   Java source line #518	-> byte code offset #611
		// Local variable table:
		//   start	length	slot	name	signature
		//   0	622	0	this	KeystoreCipherProviderImpl
		//   0	622	1	clientId	String
		//   0	622	2	props	Properties
		//   1	401	3	inputFile	java.io.InputStream
		//   408	67	3	kse	java.security.KeyStoreException
		//   479	85	3	uke	java.security.UnrecoverableKeyException
		//   568	2	3	sce	SecurityConfigurationException
		//   571	47	3	e	Exception
		//   15	254	4	clientKeyStore	java.security.KeyStore
		//   448	25	4	msg	String
		//   538	24	4	msg	String
		//   591	25	4	msg	String
		//   30	59	5	re	RuntimeException
		//   136	17	5	msg	String
		//   176	69	5	ioe	java.io.IOException
		//   266	11	5	keyPassword	java.security.KeyStore.PasswordProtection
		//   70	17	6	msg	String
		//   226	17	6	msg	String
		//   284	85	6	pkEntry	java.security.KeyStore.PrivateKeyEntry
		//   339	54	7	msg	String
		//   395	11	8	localObject	Object
		// Exception table:
		//   from	to	target	type
		//   17	27	30	java/lang/RuntimeException
		//   158	173	176	java/io/IOException
		//   2	384	395	finally
		//   395	397	395	finally
		//   0	392	408	java/security/KeyStoreException
		//   395	408	408	java/security/KeyStoreException
		//   0	392	479	java/security/UnrecoverableKeyException
		//   395	408	479	java/security/UnrecoverableKeyException
		//   0	392	568	com/fedex/security/exceptions/SecurityConfigurationException
		//   395	408	568	com/fedex/security/exceptions/SecurityConfigurationException
		//   0	392	571	java/lang/Exception
		//   395	408	571	java/lang/Exception
		return new Date();
	}

	public static void cancelRotationTimer() {
		if (rotationTimer != null) {
			rotationTimer.cancel();
		}
	}

	public String getCDSUrl() {
		return this.cdsUrl;
	}

	public boolean getAutoCertRotationFlag() {
		return this.autoCertRotation;
	}

	public static Date getCertExprDate() {
		return new Date(certExprDate.getTime());
	}

	public static String getAbsolutePathOfClientFile() {
		return absolutePathOfClientFile;
	}

	public static void setAbsolutePathOfClientFile(String absolutePathOfClientFile) {
		absolutePathOfClientFile = absolutePathOfClientFile;
	}

	public static String getAbsolutePathOfCert() {
		return absolutePathOfCert;
	}

	public static void setAbsolutePathOfCert(String absolutePathOfCert) {
		absolutePathOfCert = absolutePathOfCert;
	}
}
