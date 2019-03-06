package com.fedex.security.server;

import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import com.fedex.security.common.CipherProvider;
import com.fedex.security.common.FileLoader;
import com.fedex.security.exceptions.SecurityConfigurationException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.security.cert.Certificate;
import javax.security.cert.X509Certificate;
import java.io.File;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;

public final class LdapCipherProviderImpl
		implements CipherProvider, RevocationProvider {
	private static final String CLIENT_CERT_DISK_CACHE_FILE = "LdapCipherProviderImpl.clientCertCache";
	private static final FileLoader localLoader = new FileLoader();
	public static final String LDAP_URL_PROP = "ldap.url";
	public static final String LDAP_APP_ID_ATTRIBUTE_PROP = "ldap.app.id.attr.name";
	public static final String LDAP_CERT_ATTRIBUTE_PROP = "ldap.cert.attr.name";
	public static final String LDAP_REVOKE_ATTRIBUTE_PROP = "ldap.revoke.attr.name";
	public static final String CIPHER_ALGORITHM_PROP = "security.api.cipher.algorithm";
	public static final String KEY_ROTATION_CHECK_IN_SECONDS_PROP = "security.api.server.cert.rotation.check";
	public static final String LOCAL_CACHE_DIR = "security.api.local.cache.dir";
	public static final String LDAP_CONN_TIMEOUT = "ldap.conn.timeout";
	public static final String LDAP_READ_TIMEOUT = "ldap.read.timeout";
	private String ldapUrl;
	private int ldapReadTimeout;
	private int ldapConnTimeout;
	private String appIdAttribute;
	private String certIdAttribute;
	private String revokeAttribute;
	private String cipherAlgorithm;
	private long certRotationCheckInSeconds;
	private Map<String, Map<BigInteger, Cipher>> clientCipherCache;
	private Map<String, List<Certificate>> clientCertCache;
	private static Timer cipherCacheTimer;
	private long cipherTimerSerial;
	private Set<String> revokedClients = Collections.synchronizedSet(new HashSet());
	private String localCacheDir;
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(LdapCipherProviderImpl.class.getName());

	private LdapCipherProviderImpl() {
		this("security.properties");
	}

	private LdapCipherProviderImpl(String pathWithPropsFileName) {
		try {
			Properties props = FileLoader.getFileAsProperties(pathWithPropsFileName);
			checkForRequiredProps(props);
			this.ldapUrl = props.getProperty("ldap.url");
			this.ldapConnTimeout = (1000 * Integer.parseInt(props.getProperty("ldap.conn.timeout")));
			this.ldapReadTimeout = (1000 * Integer.parseInt(props.getProperty("ldap.read.timeout")));
			this.appIdAttribute = props.getProperty("ldap.app.id.attr.name");
			this.certIdAttribute = props.getProperty("ldap.cert.attr.name");
			this.revokeAttribute = props.getProperty("ldap.revoke.attr.name");
			this.certRotationCheckInSeconds = Long.parseLong(props.getProperty("security.api.server.cert.rotation.check"));
			this.localCacheDir = props.getProperty("security.api.local.cache.dir");
			new File(this.localCacheDir).mkdirs();
			this.cipherAlgorithm = props.getProperty("security.api.cipher.algorithm");
			this.clientCipherCache = Collections.synchronizedMap(new HashMap());
			this.clientCertCache = Collections.synchronizedMap(new HashMap());
			Object fromDisk = localLoader.readObjectFromDisk(this.localCacheDir + File.separator + "LdapCipherProviderImpl.clientCertCache");
			if ((fromDisk != null) && ((fromDisk instanceof Map))) {
				try {
					Map<String, List<Certificate>> clientCertCacheFromDisk = (Map)fromDisk;
					if ((clientCertCacheFromDisk != null) && (clientCertCacheFromDisk.size() > 0)) {
						this.clientCertCache.putAll(clientCertCacheFromDisk);
					}
				}
				catch (Exception e) {
					logger.error(new FedExLogEntry("Failed to configure cert cache. Path to the local cache directory is missing from the security.properties file: "), e);
				}
			}
			fromDisk = null;
			logger.info(new FedExLogEntry("LdapCipherProviderImpl instance created"));
			logger.info(new FedExLogEntry("LdapCipherProviderImpl rotation timer started"));
		}
		catch (Exception e) {
			String msg = "Failed to configure LdapCipherProviderImpl due to invalid values provided for properties, exiting.  Invalid property in security.properties file.";
			logger.fatal(new FedExLogEntry("Failed to configure LdapCipherProviderImpl due to invalid values provided for properties, exiting.  Invalid property in security.properties file."), e);
			throw new SecurityConfigurationException("Failed to configure LdapCipherProviderImpl due to invalid values provided for properties, exiting.  Invalid property in security.properties file.", e);
		}
	}

	private static final class LdapCipherProviderImplHolder {
		private static LdapCipherProviderImpl instance = null;

		public static LdapCipherProviderImpl getInstance() {
			if (instance == null) {
				instance = new LdapCipherProviderImpl(null);
			}
			return instance;
		}

		public static LdapCipherProviderImpl getInstance(String propsFile) {
			if (instance == null) {
				instance = new LdapCipherProviderImpl(propsFile);
			}
			return instance;
		}
	}

	public static final LdapCipherProviderImpl getInstance()
			throws SecurityConfigurationException {
		return LdapCipherProviderImplHolder.getInstance();
	}

	public static final LdapCipherProviderImpl getInstance(String propsFile) {
		return LdapCipherProviderImplHolder.getInstance(propsFile);
	}

	public final void configure(String clientId, Properties props) {
	}

	public final boolean isConfigured(String clientId) {
		return true;
	}

	public Cipher[] getDecryptionCiphers(String clientId) {
		return getDecryptionCiphers(clientId, false);
	}

	public Cipher[] getDecryptionCiphers(String clientId, boolean ignoreCache) {
		if ((!ignoreCache) && (this.clientCipherCache.containsKey(clientId))) {
			return cacheToCipher(this.clientCipherCache.get(clientId));
		}
		try {
			Certificate[] clientCerts = getCertificates(clientId);
			if (clientCerts == null) {
				return null;
			}
			Map<BigInteger, Cipher> cachedCiphers = null;
			if ((this.clientCipherCache != null) && (this.clientCipherCache.containsKey(clientId))) {
				cachedCiphers = this.clientCipherCache.get(clientId);
			}
			Map<BigInteger, Cipher> newCiphers = new HashMap();
			for (Certificate cert : clientCerts) {
				BigInteger serial = ((X509Certificate)cert).getSerialNumber();
				if ((cachedCiphers != null) && (cachedCiphers.containsKey(serial))) {
					newCiphers.put(serial, cachedCiphers.get(serial));
				}
				else {
					Cipher cipher = Cipher.getInstance(this.cipherAlgorithm);
					cipher.init(2, cert.getPublicKey());
					newCiphers.put(serial, cipher);
					logger.trace(new FedExLogEntry("Built cipher for client " + clientId + " using certificate " + ((X509Certificate)cert).getSerialNumber()));
				}
			}
			this.clientCipherCache.put(clientId, newCiphers);
			return cacheToCipher(this.clientCipherCache.get(clientId));
		}
		catch (NoSuchPaddingException nspe) {
			logger.warn(new FedExLogEntry("No Such Padding Exception when attemting to encrypt token. Possibly an invalid character in the token."));
			throw new RuntimeException("Unable to create cipher", nspe);
		}
		catch (InvalidKeyException ike) {
			logger.warn(new FedExLogEntry("Invalid Key Exception when attemting to encrypt token. Possibly a certificate in the wrong environment (ex. Prod cert in test environment)."));
			throw new RuntimeException("Unable to create cipher", ike);
		}
		catch (NoSuchAlgorithmException nsae) {
			logger.warn(new FedExLogEntry("No Such Algorithm Exception when attemting to encrypt token.  The API was unable to decrypt the token."));
			throw new RuntimeException("Unable to create cipher", nsae);
		}
	}

	public void resetDecryptionCipher(String clientId, Cipher cipher) {
		try {
			Certificate[] clientCerts = getCertificates(clientId);
			if (clientCerts == null) {
				logger.trace(new FedExLogEntry("Cannot reset decryption cipher for " + clientId + ". No client certificates found in LDAP."));
			}
			else {
				Map<BigInteger, Cipher> ciphers = this.clientCipherCache.get(clientId);
				for (BigInteger serial : ciphers.keySet()) {
					Cipher c = ciphers.get(serial);
					if (c == cipher) {
						for (int i = 0; i < clientCerts.length; i++) {
							if (((X509Certificate)clientCerts[i]).getSerialNumber() == serial) {
								cipher.init(2, clientCerts[i].getPublicKey());
								logger.trace(new FedExLogEntry("Decryption cipher " + cipher + " successfully reset for " + clientId + " using certificate " + ((X509Certificate)clientCerts[0]).getSerialNumber()));
							}
						}
					}
				}
			}
		}
		catch (InvalidKeyException ike) {
			logger.warn(new FedExLogEntry("Certificate stored in LDAP does not match certificate stored with client. Verify certificate in client and LDAP match."));
			throw new RuntimeException("Unable to reset cipher", ike);
		}
	}

	public boolean isClientRevoked(String clientId) {
		return this.revokedClients.contains(clientId);
	}

	private final Certificate[] getCertificates(String clientId) {
		ArrayList<Certificate> certList = new ArrayList();
		DirContext context = null;
		try {
			Hashtable<String, String> ldapEnv = new Hashtable();
			ldapEnv.put("java.naming.provider.url", this.ldapUrl);
			ldapEnv.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory");
			ldapEnv.put("com.sun.jndi.ldap.connect.timeout", this.ldapConnTimeout + "");
			ldapEnv.put("com.sun.jndi.ldap.read.timeout", this.ldapReadTimeout + "");
			ldapEnv.put("java.naming.ldap.attributes.binary", this.certIdAttribute);
			context = new InitialDirContext(ldapEnv);
			SearchControls controls = new SearchControls();
			controls.setSearchScope(2);
			controls.setReturningAttributes(new String[]{this.certIdAttribute, this.revokeAttribute});
			NamingEnumeration<SearchResult> results = context.search("", this.appIdAttribute + "=" + clientId, controls);
			if (!results.hasMore()) {
				logger.warn(new FedExLogEntry("Application account not found in LDAP for client/ no certificates existin LDAP for this client " + clientId));
			}
			else {
				SearchResult result = results.next();
				Attributes attr = result.getAttributes();
				if (attr.get(this.revokeAttribute) != null) {
					this.revokedClients.add(clientId);
				}
				else {
					this.revokedClients.remove(clientId);
					NamingEnumeration<?> attribs = attr.get(this.certIdAttribute).getAll();
					boolean flag = true;
					while (attribs.hasMore()) {
						Object a = attribs.next();
						X509Certificate cert = X509Certificate.getInstance((byte[])a);
						if (cert.getNotAfter().after(new Date())) {
							logger.trace(new FedExLogEntry("LdapPublicKeyProviderImpl retrieved certificate " + cert.getSerialNumber() + " for client " + clientId));
							certList.add(cert);
							flag = false;
						}
						else {
							if (flag) {
								logger.info(new FedExLogEntry("Client security certificate has expired." + cert.getSerialNumber() + " for client " + clientId));
							}
						}
					}
					if (flag) {
						logger.warn(new FedExLogEntry("Client security certificate has expired. for client " + clientId));
					}
				}
			}
			try {
				if (context != null) {
					context.close();
				}
			}
			catch (Exception e) {
				logger.warn(new FedExLogEntry("Exception encountered closing ldap connection: " + e.getMessage()), e);
			}
//			if (certList == null) {
//				break label963;
//			}
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Can't retrieve public certificate for client: " + clientId + ". Possible connection failure with LDAP: " + e.getMessage()), e);
			certList = null;
		}
		finally {
			try {
				if (context != null) {
					context.close();
				}
			}
			catch (Exception e) {
				logger.warn(new FedExLogEntry("Exception encountered closing ldap connection: " + e.getMessage()), e);
			}
		}
		if (certList.isEmpty()) {
			List<Certificate> cachedCerts = this.clientCertCache.get(clientId);
			if (cachedCerts != null) {
				certList = new ArrayList();
				for (Certificate cert : cachedCerts) {
					X509Certificate c = (X509Certificate)cert;
					if (c.getNotAfter().after(new Date())) {
						certList.add(cert);
						logger.trace(new FedExLogEntry("LdapPublicKeyProviderImpl retrieved certificate using LKG " + c.getSerialNumber() + " for client " + clientId));
					}
					else {
						logger.warn(new FedExLogEntry("LdapPublicKeyProviderImpl encountered expired certificate using LKG " + c.getSerialNumber() + " for client " + clientId));
					}
				}
			}
		}
		else {
			List<Certificate> cachedCerts = this.clientCertCache.get(clientId);
			if ((cachedCerts == null) || (!certList.equals(cachedCerts))) {
				this.clientCertCache.put(clientId, certList);
				localLoader.saveObjectToDisk(this.localCacheDir + File.separator + "LdapCipherProviderImpl.clientCertCache", this.clientCertCache);
				logger.trace(new FedExLogEntry("Updating LKG for client " + clientId));
			}
		}
		if (!certList.isEmpty()) {
			return certList.toArray(new Certificate[certList.size()]);
		}
		return null;
	}

	private void refreshCiphers() {
		for (String clientId : this.clientCipherCache.keySet()) {
			try {
				getDecryptionCiphers(clientId, true);
			}
			catch (Exception e) {
				logger.warn(new FedExLogEntry("Exception obtaining decryption ciphers"), e);
				throw new RuntimeException("Unable to get decryption cipher", e);
			}
		}
	}

	private class ClientCipherCacheTask
			extends TimerTask {
		private ClientCipherCacheTask() {
		}

		public void run() {
			LdapCipherProviderImpl.logger.trace(new FedExLogEntry("LdapCipherProviderImpl timer cache running."));
			LdapCipherProviderImpl.this.refreshCiphers();
		}
	}

	private void manageTimers() {
		if (this.cipherTimerSerial < System.currentTimeMillis() - 2L * this.certRotationCheckInSeconds * 1000L) {
			if (cipherCacheTimer != null) {
				cipherCacheTimer.cancel();
				cipherCacheTimer = null;
			}
			cipherCacheTimer = new Timer(true);
			cipherCacheTimer.schedule(new ClientCipherCacheTask(), this.certRotationCheckInSeconds * 1000L, this.certRotationCheckInSeconds * 1000L);
			this.cipherTimerSerial = System.currentTimeMillis();
			logger.info(new FedExLogEntry("Rotation timer (re)started"));
		}
		else {
			logger.trace(new FedExLogEntry("Rotation timer status OK"));
		}
	}

	private Cipher[] cacheToCipher(Map<BigInteger, Cipher> cachedCiphers) {
		if (cachedCiphers == null) {
			return null;
		}
		return cachedCiphers.values().toArray(new Cipher[cachedCiphers.size()]);
	}

	public void setRotationCallback(CipherProvider.RotationCallback callback) {
	}

	public Cipher getEncryptionCipher(String clientId) {
		return null;
	}

	public Cipher getEncryptionCipher(String clientId, boolean ignoreCache) {
		return null;
	}

	private void checkForRequiredProps(Properties props) {
		boolean isExist = true;
		StringBuffer errMsg = new StringBuffer();
		if (!props.containsKey("security.api.cipher.algorithm")) {
			errMsg = errMsg.append("'security.api.cipher.algorithm' is missing\n");
			isExist = false;
		}
		if (!props.containsKey("security.api.server.cert.rotation.check")) {
			errMsg = errMsg.append("'security.api.server.cert.rotation.check' is missing\n");
			isExist = false;
		}
		if (!props.containsKey("ldap.url")) {
			errMsg = errMsg.append("'ldap.url' missing\n");
			isExist = false;
		}
		if (!props.containsKey("ldap.app.id.attr.name")) {
			errMsg = errMsg.append("'ldap.app.id.attr.name' is missing\n");
			isExist = false;
		}
		if (!props.containsKey("ldap.cert.attr.name")) {
			errMsg = errMsg.append("'ldap.cert.attr.name' is missing\n");
			isExist = false;
		}
		if (!props.containsKey("ldap.revoke.attr.name")) {
			errMsg = errMsg.append("'ldap.revoke.attr.name' is missing\n");
			isExist = false;
		}
		if (!props.containsKey("ldap.conn.timeout")) {
			errMsg = errMsg.append("'ldap.conn.timeout' is missing\n");
			isExist = false;
		}
		if (!props.containsKey("ldap.read.timeout")) {
			errMsg = errMsg.append("'ldap.read.timeout' is missing\n");
			isExist = false;
		}
		if (!props.containsKey("security.api.local.cache.dir")) {
			errMsg = errMsg.append("'security.api.local.cache.dir' is missing\n");
			isExist = false;
		}
		if (!isExist) {
			String msg = "Failed to configure LdapCipherProviderImpl due to missing values provided for properties, exiting. Missing or invalid property in security.properties file.";
			logger.fatal(new FedExLogEntry("Failed to configure LdapCipherProviderImpl due to missing values provided for properties, exiting. Missing or invalid property in security.properties file. " + errMsg));
			throw new SecurityConfigurationException("Failed to configure LdapCipherProviderImpl due to missing values provided for properties, exiting. Missing or invalid property in security.properties file." + errMsg);
		}
	}

	public static void cancelTimerTask() {
		if (cipherCacheTimer != null) {
			cipherCacheTimer.cancel();
		}
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\server\LdapCipherProviderImpl.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */