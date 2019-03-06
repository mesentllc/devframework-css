package com.fedex.security.server;

import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import com.fedex.security.common.FileLoader;
import com.fedex.security.exceptions.AuthenticationFailureException;
import com.fedex.security.exceptions.SecurityConfigurationException;
import sun.misc.BASE64Decoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.IOException;
import java.security.Principal;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class PkcTokenAuthenticatorImpl
		implements Authenticator {
	public static final String TOKEN_MAX_TTL_IN_SECONDS_PROP = "security.api.token.max.ttl";
	private long tokenMaxTtlInSeconds;
	private long maxCacheSizePerService;
	private Map<String, Map<String, ClientPrincipal>> clientAuthnCache;
	private Map<String, Long> lastClientRetry;
	private static final long minClientRetryInSeconds = 60L;
	private static final long maxCacheSizeOverall = 10000L;
	private static final String MAX_CACHE_SIZE_PER_SERVICE = "security.api.service.cache";
	private static final long SERVER_MILLIS_OFFSET_ALLOWANCE = 54000000L;
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(PkcTokenAuthenticatorImpl.class.getName());
	private static final FedExLoggerInterface auditLogger = FedExLogger.getAuditLogger();
	private static final SimpleDateFormat auditDateFormat = new SimpleDateFormat("yyyyMMddhh24mmss");
	private static final long CIPHER_REFRESH_INTERVAL = 86400000L;
	private long last_query_time = 0L;

	private PkcTokenAuthenticatorImpl() {
		this("security.properties");
	}

	private PkcTokenAuthenticatorImpl(String pathWithPropsFileName) {
		Properties props = verifyProperties(FileLoader.getFileAsProperties(pathWithPropsFileName));
		this.tokenMaxTtlInSeconds = Long.parseLong(props.getProperty("security.api.token.max.ttl"));
		logger.info(new FedExLogEntry("PkcTokenAuthenticatorImpl instance created"));
		this.lastClientRetry = new ConcurrentHashMap();
		this.clientAuthnCache = new ConcurrentHashMap();
		logger.info(new FedExLogEntry("Caches initialized"));
		this.maxCacheSizePerService = Long.parseLong(props.getProperty("security.api.service.cache"));
		logger.info(new FedExLogEntry("Max Cache Size Per Service: " + this.maxCacheSizePerService));
		this.last_query_time = System.currentTimeMillis();
	}

	private static final class PkcTokenAuthenticatorImplHolder {
		private static PkcTokenAuthenticatorImpl instance = null;

		public static PkcTokenAuthenticatorImpl getInstance() {
			if (instance == null) {
				instance = new PkcTokenAuthenticatorImpl(null);
			}
			return instance;
		}

		public static PkcTokenAuthenticatorImpl getInstance(String propsFile) {
			if (instance == null) {
				instance = new PkcTokenAuthenticatorImpl(propsFile);
			}
			return instance;
		}
	}

	public static final PkcTokenAuthenticatorImpl getInstance() {
		return PkcTokenAuthenticatorImplHolder.getInstance();
	}

	public static final PkcTokenAuthenticatorImpl getInstance(String propsFile) {
		return PkcTokenAuthenticatorImplHolder.getInstance(propsFile);
	}

	public final Principal authenticate(String token, String serviceName)
			throws AuthenticationFailureException {
		String clientId = null;
		try {
			if ((token == null) || (serviceName == null) || (token.split(":").length != 4)) {
				boolean badValue = false;
				String msg = "Bad value passed to authenticate() method:";
				if (token == null) {
					badValue = true;
					msg = "Token is null.";
				}
				else {
					if (token.split(":").length != 4) {
						badValue = true;
						msg = "Token is invalid.";
					}
				}
				if (serviceName == null) {
					badValue = true;
					msg = "ServiceName is null.";
				}
				if (badValue) {
					writeAuditLogRecord(clientId, serviceName, false, AuthenticationFailureException.ReasonCode.GENERAL_FAILURE);
					logger.trace(new FedExLogEntry(msg));
					throw new AuthenticationFailureException(AuthenticationFailureException.ReasonCode.GENERAL_FAILURE, msg);
				}
			}
			String[] splitToken = token.split(":");
			clientId = splitToken[1];
			if (System.currentTimeMillis() - this.last_query_time >= 86400000L) {
				ServerCipherProviderFactory.getProvider().getDecryptionCiphers(clientId, true);
				this.last_query_time = System.currentTimeMillis();
			}
			return doAuthenticate(token, serviceName);
		}
		catch (AuthenticationFailureException afe) {
			logger.warn(new FedExLogEntry("Authentication Failure: Reason Code = " + afe.getReasonCode()), afe);
			if ((AuthenticationFailureException.ReasonCode.CLIENT_MISMATCH.equals(afe.getReasonCode())) || (AuthenticationFailureException.ReasonCode.CLIENT_REVOKED.equals(afe.getReasonCode()))) {
				if ((!this.lastClientRetry.containsKey(clientId)) || (this.lastClientRetry.get(clientId).longValue() < System.currentTimeMillis() - 60000L)) {
					logger.trace(new FedExLogEntry("Authentication failed, retrying token."));
					try {
						logger.trace(new FedExLogEntry("Updating the last client retry..."));
						this.lastClientRetry.put(clientId, Long.valueOf(System.currentTimeMillis()));
						logger.trace(new FedExLogEntry("Getting new decryption ciphers, ignoring cache..."));
						ServerCipherProviderFactory.getProvider().getDecryptionCiphers(clientId, true);
						logger.trace(new FedExLogEntry("Try doAuthenticate one more time"));
						return doAuthenticate(token, serviceName);
					}
					catch (SecurityConfigurationException sce) {
						logger.warn(new FedExLogEntry(sce.getMessage()), sce);
						throw new RuntimeException(sce);
					}
				}
			}
			throw afe;
		}
		catch (Exception e) {
			writeAuditLogRecord(clientId, serviceName, false, AuthenticationFailureException.ReasonCode.API_ERROR);
			logger.trace(new FedExLogEntry("Major Token Authentication Failure: " + e.getMessage()));
			throw new AuthenticationFailureException(AuthenticationFailureException.ReasonCode.API_ERROR, "An unexpected error has occured in the API, please examine any surrounding error messages to determine the cause", e);
		}
	}

	private final Principal doAuthenticate(String token, String serviceName)
			throws AuthenticationFailureException {
		String[] splitToken = token.split(":");
		String version = splitToken[0];
		String clientId = splitToken[1];
		String cipherText = splitToken[2];
		String onBehalfOf = splitToken[3];
		StringBuilder authenticationErrorMessage = new StringBuilder();
		Map<String, ClientPrincipal> clientCacheForService;
		if (this.clientAuthnCache.containsKey(serviceName)) {
			clientCacheForService = this.clientAuthnCache.get(serviceName);
		}
		else {
			clientCacheForService = new ConcurrentHashMap();
		}
		if (clientCacheForService.size() >= this.maxCacheSizePerService) {
			purgeCacheForService(serviceName, clientCacheForService);
		}
		ClientPrincipal principal = null;
		logger.trace(new FedExLogEntry("Searching for client token in the cache for serviceName..."));
		if ((principal = clientCacheForService.get(cipherText)) != null) {
			logger.trace(new FedExLogEntry("Found client token in the cache for serviceName, testing it..."));
			if (principal.getCreateTimestamp() + this.tokenMaxTtlInSeconds * 1000L > System.currentTimeMillis()) {
				writeAuditLogRecord(clientId, serviceName, true, null);
				logger.trace(new FedExLogEntry("Client token from cache is valid, returning ClientPrincipal."));
				return new ClientPrincipal(principal.getClientId(), onBehalfOf, token, principal.getCreateTimestamp());
			}
			logger.trace(new FedExLogEntry("Client token has expired, removing from cache..."));
			logger.debug(new FedExLogEntry("### Not using cached token, this is the new one for clientId = " + clientId + " and serviceName = " + serviceName));
			clientCacheForService.remove(cipherText);
		}
		else {
			logger.debug(new FedExLogEntry("### There isn't a token match in the cache at this instant..."));
		}
		Cipher[] clientCiphers = null;
		try {
			logger.trace(new FedExLogEntry("Getting decryption ciphers for clientId " + clientId + "..."));
			clientCiphers = ServerCipherProviderFactory.getProvider().getDecryptionCiphers(clientId);
			if (RevocationProviderFactory.getProvider().isClientRevoked(clientId)) {
				writeAuditLogRecord(clientId, serviceName, false, AuthenticationFailureException.ReasonCode.CLIENT_REVOKED);
				logger.trace(new FedExLogEntry("LDAP reporting that client " + clientId + " has been revoked."));
				throw new AuthenticationFailureException(AuthenticationFailureException.ReasonCode.CLIENT_REVOKED, "Access for client " + clientId + " has been revoked; authentication not attempted");
			}
			if (clientCiphers == null) {
				writeAuditLogRecord(clientId, serviceName, false, AuthenticationFailureException.ReasonCode.INVALID_CLIENT);
				logger.trace(new FedExLogEntry("LDAP reporting that no keys are available for client " + clientId + "."));
				throw new AuthenticationFailureException(AuthenticationFailureException.ReasonCode.INVALID_CLIENT, "No keys found for client " + clientId + ", " + ", authentication cannot be performed");
			}
		}
		catch (SecurityConfigurationException sce) {
			logger.warn(new FedExLogEntry(sce.getMessage()));
			throw new RuntimeException(sce);
		}
		logger.trace(new FedExLogEntry("Validating authentication token for client " + clientId));
		boolean wrongClient = false;
		for (Cipher cipher : clientCiphers) {
			wrongClient = false;
			try {
				String[] splitResult = null;
				synchronized (cipher) {
					try {
						if (this.clientAuthnCache.containsKey(serviceName)) {
							clientCacheForService = this.clientAuthnCache.get(serviceName);
							if ((principal = clientCacheForService.get(cipherText)) != null) {
								if (principal.getCreateTimestamp() + this.tokenMaxTtlInSeconds * 1000L > System.currentTimeMillis()) {
									writeAuditLogRecord(clientId, serviceName, true, null);
									logger.trace(new FedExLogEntry("Found new token in cache, returning ClientPrincipal."));
									logger.debug(new FedExLogEntry("### (S) Found new token in cache, exiting synchronized block..."));
									return new ClientPrincipal(principal.getClientId(), onBehalfOf, token, principal.getCreateTimestamp());
								}
								logger.debug(new FedExLogEntry("### (S) Somehow we managed to find an expired token at this point, better remove it..."));
								clientCacheForService.remove(cipherText);
							}
							else {
								logger.debug(new FedExLogEntry("### (S) No luck with the double check, new token not there yet..."));
							}
						}
						else {
							logger.debug(new FedExLogEntry("### (S) No luck with the double check, service name not there yet..."));
						}
						splitResult = new String(cipher.doFinal(new BASE64Decoder().decodeBuffer(cipherText))).split(":");
					}
					catch (BadPaddingException bpe) {
						ServerCipherProviderFactory.getProvider().resetDecryptionCipher(clientId, cipher);
						throw bpe;
					}
					catch (IllegalBlockSizeException ibse) {
						ServerCipherProviderFactory.getProvider().resetDecryptionCipher(clientId, cipher);
						throw ibse;
					}
					catch (IOException ioe) {
						ServerCipherProviderFactory.getProvider().resetDecryptionCipher(clientId, cipher);
						throw ioe;
					}
					logger.debug(new FedExLogEntry("### (S) Done with sync block..."));
				}
				logger.trace(new FedExLogEntry("Finished with cipher and decrypting cipherText..."));
				String serviceNameFromToken = splitResult[0];
				long createTimestamp = Long.parseLong(splitResult[1]);
				if ((serviceNameFromToken != null) && (serviceNameFromToken.equalsIgnoreCase(serviceName))) {
					logger.trace(new FedExLogEntry("Service Name from Token matches mine..."));
					if ((createTimestamp <= System.currentTimeMillis() + 54000000L) && (createTimestamp + this.tokenMaxTtlInSeconds * 1000L > System.currentTimeMillis())) {
						logger.trace(new FedExLogEntry("Creating new client principal..."));
						ClientPrincipal principal2 = new ClientPrincipal(clientId, onBehalfOf, cipherText, createTimestamp);
						logger.trace(new FedExLogEntry("Placing the new client principal in the Map into the cache..."));
						clientCacheForService.put(cipherText, principal2);
						this.clientAuthnCache.put(serviceName, clientCacheForService);
						logger.debug(new FedExLogEntry("### Placed the new client principal in the Map into the cache..."));
						writeAuditLogRecord(clientId, serviceName, true, null);
						return principal2;
					}
					writeAuditLogRecord(clientId, serviceName, false, AuthenticationFailureException.ReasonCode.EXPIRED_TOKEN);
					logger.trace(new FedExLogEntry("The token provided by the client " + clientId + " has expired."));
					throw new AuthenticationFailureException(AuthenticationFailureException.ReasonCode.EXPIRED_TOKEN, "The token provided for client " + clientId + " has expired, generate a new token and attempt this request again");
				}
				writeAuditLogRecord(clientId, serviceName, false, AuthenticationFailureException.ReasonCode.SERVICE_MISMATCH);
				logger.trace(new FedExLogEntry("The token provided by client " + clientId + " was not generated for this service." + " Verify the service name that the client used to generate the token matches the destination service name."));
				throw new AuthenticationFailureException(AuthenticationFailureException.ReasonCode.SERVICE_MISMATCH, "The token provided by client " + clientId + " was not generated for this service");
			}
			catch (BadPaddingException bpe) {
				logger.trace(new FedExLogEntry("Bad Padding Exception when attemting to decrypt token. Possibly a key mismatch with LDAP " + bpe.getMessage()));
				authenticationErrorMessage.append("Bad Padding Exception when attemting to decrypt token. Possibly a key mismatch with LDAP " + bpe.getMessage());
				wrongClient = true;
			}
			catch (IllegalBlockSizeException ibse) {
				logger.trace(new FedExLogEntry("Illegal Block Size Exception when attemting to decrypt token. Possibly a certificate in the wrong environment (ex. Prod cert in test environment). Exception: " + ibse.getMessage()));
				authenticationErrorMessage.append("Illegal Block Size Exception when attemting to decrypt token. Possibly a certificate in the wrong environment (ex. Prod cert in test environment). Exception: " + ibse.getMessage());
				wrongClient = true;
			}
			catch (IOException ioe) {
				logger.trace(new FedExLogEntry("IO Exception when attemting to decrypt token. The API was unable to decrypt the token. Exception: " + ioe.getMessage()));
				wrongClient = true;
				authenticationErrorMessage.append("IO Exception when attemting to decrypt token. The API was unable to decrypt the token. Exception: " + ioe.getMessage());
			}
			catch (AuthenticationFailureException afe) {
				throw afe;
			}
			catch (Exception e) {
				logger.warn(new FedExLogEntry("Unexpected exception attempting to decrypt token for client " + clientId + ": " + e.getMessage()));
			}
		}
		if (wrongClient) {
			writeAuditLogRecord(clientId, serviceName, false, AuthenticationFailureException.ReasonCode.CLIENT_MISMATCH);
			logger.trace(new FedExLogEntry("Unable to decrypt token with available certificates. Check for a mismatched client ID." + authenticationErrorMessage.toString()));
			throw new AuthenticationFailureException(AuthenticationFailureException.ReasonCode.CLIENT_MISMATCH, "The token received could not be processed by any of the keys for client " + clientId + ". " + authenticationErrorMessage.toString());
		}
		writeAuditLogRecord(clientId, serviceName, false, AuthenticationFailureException.ReasonCode.GENERAL_FAILURE);
		logger.trace(new FedExLogEntry("Failure that was not anticipated, please review previous trace entries to help determine root cause..."));
		throw new AuthenticationFailureException(AuthenticationFailureException.ReasonCode.GENERAL_FAILURE, "A general failure occurred attempting to decrypt the token for client " + clientId + ", review log for additional messages.");
	}

	private static void writeAuditLogRecord(String clientId, String serviceName, boolean authnd, AuthenticationFailureException.ReasonCode reason) {
		auditLogger.info(new FedExLogEntry(auditDateFormat.format(new Date()) + "|authn|" + clientId + "|" + serviceName + "|" + authnd + "|" + reason));
	}

	public final int currentServiceCacheSize() {
		return this.clientAuthnCache.size();
	}

	public final int currentClientCacheSizeForService(String serviceName) {
		int size = 0;
		if (this.clientAuthnCache.containsKey(serviceName)) {
			Map<String, ClientPrincipal> clientCacheForService = this.clientAuthnCache.get(serviceName);
			size = clientCacheForService.size();
		}
		return size;
	}

	public final long currentOverallCacheSize() {
		logger.trace(new FedExLogEntry("Calculating cache size for all services"));
		long size = 0L;
		Set<String> serviceNames = this.clientAuthnCache.keySet();
		for (String svc : serviceNames) {
			int persvc = 0;
			if (this.clientAuthnCache.containsKey(svc)) {
				Map<String, ClientPrincipal> clientCacheForService = this.clientAuthnCache.get(svc);
				persvc = clientCacheForService.size();
			}
			size += persvc;
		}
		return size;
	}

	public final void purgeCacheForService(String serviceName) {
		logger.trace(new FedExLogEntry("Purging expired tokens in cache for service: " + serviceName));
		long ttl = 1000L * this.tokenMaxTtlInSeconds;
		long currentTime = System.currentTimeMillis();
		Map<String, ClientPrincipal> clientCacheForService;
		if (this.clientAuthnCache.containsKey(serviceName)) {
			clientCacheForService = this.clientAuthnCache.get(serviceName);
			Set<String> cipherTexts = clientCacheForService.keySet();
			for (String cipherText : cipherTexts) {
				ClientPrincipal principal = clientCacheForService.get(cipherText);
				if (currentTime > principal.getCreateTimestamp() + ttl) {
					logger.trace(new FedExLogEntry("Cipher Text of Client ID : " + principal.getClientId() + " for service " + serviceName + " has expired, removing from cache."));
					clientCacheForService.remove(cipherText);
				}
			}
		}
		else {
			logger.trace(new FedExLogEntry("No tokens found in cache for service name " + serviceName + " to expire."));
		}
	}

	public final void purgeCacheForService(String serviceName, Map<String, ClientPrincipal> clientCacheForService) {
		logger.trace(new FedExLogEntry("Purging expired tokens in cache for service: " + serviceName));
		long ttl = 1000L * this.tokenMaxTtlInSeconds;
		Set<String> cipherTexts = clientCacheForService.keySet();
		for (String cipherText : cipherTexts) {
			ClientPrincipal principal = clientCacheForService.get(cipherText);
			if (System.currentTimeMillis() > principal.getCreateTimestamp() + ttl) {
				logger.trace(new FedExLogEntry("Client token cipherText: " + cipherText + " for service " + serviceName + " has expired, removing from cache."));
				clientCacheForService.remove(cipherText);
			}
		}
	}

	public final void purgeCacheForAllServices() {
		logger.trace(new FedExLogEntry("Purging expired tokens in cache for all services"));
		Set<String> serviceNames = this.clientAuthnCache.keySet();
		String svc;
		for (Iterator i$ = serviceNames.iterator(); i$.hasNext(); purgeCacheForService(svc)) {
			svc = (String)i$.next();
		}
	}

	private Properties verifyProperties(Properties props) {
		boolean badProp = false;
		String msg = "Failed to configure authenticator";
		if (!props.containsKey("security.api.token.max.ttl")) {
			badProp = true;
			msg = msg + " Missing TOKEN_MAX_TTL_IN_SECONDS_PROP property in security.properties file.";
		}
		if (!props.containsKey("security.api.service.cache")) {
			badProp = true;
			msg = msg + " Missing MAX_CACHE_SIZE_PER_SERVICE property in security.properties file.";
		}
		if (badProp) {
			logger.fatal(new FedExLogEntry(msg));
			throw new RuntimeException(msg);
		}
		return props;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\server\PkcTokenAuthenticatorImpl.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */