package com.fedex.security.client;

import com.fedex.cds.authZ.keyStore.jaxb.KeystoreStanza;
import com.fedex.cds.client.security.ClientInvocationContext;
import com.fedex.cds.client.security.MyHandlerResolver;
import com.fedex.framework.cds.CDS;
import com.fedex.framework.cds.CDSService;
import com.fedex.framework.cds.IndexElementType;
import com.fedex.framework.cds.IndexQueryRequest;
import com.fedex.framework.cds.IndexQueryResponse;
import com.fedex.framework.cds.KeyedStanzasType;
import com.fedex.framework.cds.ObjectFactory;
import com.fedex.framework.cds.PagingRequestType;
import com.fedex.framework.cds.StanzaIdType;
import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import com.fedex.framework.utility.FedExAppFrameworkProperties;
import com.fedex.security.common.FileLoader;
import com.fedex.security.common.StringUtils;
import com.fedex.security.exceptions.AuthenticationFailureException;
import com.fedex.security.exceptions.SecurityConfigurationException;
import com.fedex.security.server.LdapCipherProviderImpl;
import com.fedex.security.server.PkcTokenAuthenticatorImpl;
import com.fedex.security.server.RevocationProviderFactory;
import com.fedex.security.server.ServerCipherProviderFactory;
import com.fedex.security.utils.SecurityUtils;
import org.w3c.dom.Element;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import javax.xml.ws.soap.SOAPFaultException;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;

public final class KeystoreRotation {
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(KeystoreRotation.class);
	private static final FedExLoggerInterface auditLogger = FedExLogger.getAuditLogger();
	private static final String auditDateFormatString = "yyyyMMddhh24mmss";
	private CDSService service;
	private static CDS port;
	private static ObjectFactory objectFactory = new ObjectFactory();
	public static final String STANZA_DESC_DOMAIN = "authZ";
	public static final String KEYSTORE_STANZA = "keystoreStanza";
	public static final int KEYSTORE_STANZA_MAJOR_VER = 1;
	public static final int KEYSTORE_STANZA_MINOR_VER = 0;
	public static final String KEYSTORE_STANZA_XPATH = "/keystoreStanza/applicationId";
	public static final String service_name = "943415_cds";
	public static final String TOKEN_VERSION = "v1";
	public static final String client_properties = "client.properties";
	public static final String client_keystore_password = "client.keystore.password";
	public static final String client_private_key_password = "client.private.key.password";
	private static final int ITEMS_PER_REQUEST = 40;
	static String cdsUrl;
	static String fileName;
	static String absolutePathOfCert;
	static String absolutePathOfClientFile;
	static boolean isBeanInit = false;

	public KeystoreRotation() {
	}

	public KeystoreRotation(String endPointUrl) {
		try {
			isBeanInit = true;
			this.service = new CDSService(new URL(endPointUrl), new QName("http://www.fedex.com/xmlns/cds2/ws", "CDSService"));
			this.service.setHandlerResolver(new MyHandlerResolver(getClientIdFromFingerPrint()));
			ClientInvocationContext.setEndpointServiceAppId("943415_cds");
			port = this.service.getCDSSoap11();
			objectFactory = new ObjectFactory();
		}
		catch (Exception e) {
			logger.error(new FedExLogEntry("The Security API is unable to connect to CDS secure URL:" + endPointUrl + e));
			logger.warn(new FedExLogEntry(" Exception being caught is :" + e));
		}
	}

	public static ObjectFactory getObjectFactoryInstance() {
		return objectFactory;
	}

	public static boolean canWrite() {
		boolean canWrite = false;
		try {
			if (!StringUtils.isNullOrBlank(absolutePathOfClientFile)) {
				File absolutePathClientPropertiesLocation = new File(absolutePathOfClientFile);
				File absolutePathCertificateLocation = new File(absolutePathOfCert);
				File ClientPropertiesDir = new File(absolutePathClientPropertiesLocation.getParent());
				File CertDir = new File(absolutePathCertificateLocation.getParent());
				if ((ClientPropertiesDir.canWrite() == true) && (CertDir.canWrite() == true)) {
					logger.info(new FedExLogEntry("The Security API is able to write to the following directories:" + ClientPropertiesDir + ";  " + CertDir));
					if ((absolutePathClientPropertiesLocation.canWrite() == true) && (absolutePathClientPropertiesLocation.isFile() == true)) {
						logger.info(new FedExLogEntry("The Security API is able to write to the client.properties file:" + absolutePathClientPropertiesLocation));
						if ((absolutePathCertificateLocation.canWrite() == true) && (absolutePathCertificateLocation.isFile() == true)) {
							logger.info(new FedExLogEntry("The Security API is able to write to the keystore:" + absolutePathCertificateLocation));
							canWrite = true;
						}
						else {
							logger.error(new FedExLogEntry("The Security API is unable to write to the keystore or it does not currently exist:" + absolutePathCertificateLocation + ".  Exists: " + absolutePathCertificateLocation.isFile() + ".  Can Write: " + absolutePathCertificateLocation.canWrite()));
						}
					}
					else {
						logger.error(new FedExLogEntry("The Security API is unable to write to the client.properties file or it does not currently exist:" + absolutePathClientPropertiesLocation + ".  Exists: " + absolutePathClientPropertiesLocation.isFile() + ".  Can Write: " + absolutePathClientPropertiesLocation.canWrite()));
					}
				}
				else {
					logger.error(new FedExLogEntry("The Security API is unable to write to the following directories:" + ClientPropertiesDir + ";  " + CertDir));
				}
			}
			else {
				logger.error(new FedExLogEntry("The Security API is unable to rotate because it cannot find the path to the client.propertiesfile."));
				canWrite = false;
			}
		}
		catch (Exception e) {
			logger.error(new FedExLogEntry("An Exception was thrown : The Security API is unable to rotate"));
			canWrite = false;
		}
		return canWrite;
	}

	public static List<IndexElementType> buildIndexQuery(String applicationId) {
		List<IndexElementType> indexElements = new ArrayList();
		IndexElementType appId = new IndexElementType();
		appId.setXpath("/keystoreStanza/applicationId");
		appId.setComparison("equals");
		appId.setValue(applicationId);
		indexElements.add(appId);
		return indexElements;
	}

	public static KeystoreStanza getKeystoreFromCDS(String appId) {
		KeystoreStanza keystoreData = null;
		StanzaIdType stanzaId = objectFactory.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("keystoreStanza");
		StanzaIdType indexStanzaId = objectFactory.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("keystoreStanza");
		try {
			IndexQueryResponse response = indexQuery(buildIndexQuery(appId), stanzaId, indexStanzaId);
			List<IndexQueryResponse.QueryItem> queryItemList = response.getQueryItem();
			JAXBContext keystoreStanzaContext = null;
			Unmarshaller unmarshaller = null;
			try {
				keystoreStanzaContext = JAXBContext.newInstance(KeystoreStanza.class);
				unmarshaller = keystoreStanzaContext.createUnmarshaller();
			}
			catch (JAXBException e) {
				logger.warn(new FedExLogEntry(" The Security API failed to retrieve the keystore from CDS : " + e.getMessage()));
				throw e;
			}
			for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
				for (KeyedStanzasType keyedStanzas : queryItem.getKeyedStanzas()) {
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						try {
							keystoreData = (KeystoreStanza)unmarshaller.unmarshal(docElement);
							if (keystoreData != null) {
								logger.info(new FedExLogEntry("The Security API successfully retrieved the keystore from CDS"));
							}
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("The Security API was unable to unmarshall the document: " + e.getMessage()));
						}
					}
				}
			}
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Caught exception e: " + e.toString()));
			throw new RuntimeException(e);
		}
		return keystoreData;
	}

	public static String updateClientProperties(String passphrase) {
		String tempDirLoc = createTempDir();
		if (StringUtils.isNullOrBlank(tempDirLoc)) {
			return tempDirLoc;
		}
		String currentClientPropsPath = absolutePathOfClientFile;
		BufferedReader br = null;
		BufferedWriter bw = null;
		try {
			FileInputStream fstream = new FileInputStream(currentClientPropsPath);
			FileOutputStream ostream = new FileOutputStream(tempDirLoc.concat("client.properties"));
			DataInputStream in = new DataInputStream(fstream);
			DataOutputStream out = new DataOutputStream(ostream);
			br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
			bw = new BufferedWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8));
			String strLine;
			while ((strLine = br.readLine()) != null) {
				if ((strLine.startsWith("client.keystore.password")) || (strLine.startsWith("client.private.key.password"))) {
					int index = strLine.indexOf("=");
					String property = strLine.substring(0, index + 1).trim();
					strLine = property.concat(passphrase);
				}
				bw.write(strLine);
				bw.newLine();
			}
			bw.flush();
			return tempDirLoc;
		}
		catch (Exception e) {
			logger.error(new FedExLogEntry("Updating Client Properties file in Temp Failed : " + e.getMessage()));
			try {
				if (FileUtil.deleteDir(new File(tempDirLoc))) {
					logger.debug(new FedExLogEntry(" Updating Client Properties failed so cleaning up the temp directory: " + tempDirLoc));
				}
			}
			catch (Exception ex) {
				logger.debug(new FedExLogEntry("Failed to delete temp directory"));
			}
			throw new RuntimeException(e);
		}
		finally {
			if (br != null) {
				try {
					br.close();
				}
				catch (IOException e) {
				}
			}
			if (bw != null) {
				try {
					bw.close();
				}
				catch (IOException e) {
				}
			}
		}
	}

	private static String validateCDSCert(String clientID)
			throws Exception {
		String tempDirLoc = "";
		try {
			KeystoreStanza keystoreData = getKeystoreFromCDS(getClientIdFromFingerPrint());
			if (keystoreData != null) {
				auditLogger.info(new FedExLogEntry(new SimpleDateFormat("yyyyMMddhh24mmss").format(new Date()) + "|keystoreStanza|" + "APP" + getClientIdFromFingerPrint() + "|" + "943415_cds" + "|read|keystore"));
				decodeCert(keystoreData);
				String passphrase = decryptPassword(keystoreData);
				tempDirLoc = updateClientProperties(passphrase);
				if (tempDirLoc.length() > 0) {
					logger.debug(new FedExLogEntry("The Security API successfully updated the client.properties file in the temp directory."));
				}
			}
		}
		catch (Exception e) {
			logger.error(new FedExLogEntry("Validation of the keystore in CDS failed : " + e.getMessage()));
			try {
				if (FileUtil.deleteDir(new File(tempDirLoc))) {
					logger.debug(new FedExLogEntry(" Validation of CDS Keystore failed so cleaning up the temp directory: " + tempDirLoc));
				}
			}
			catch (Exception ex) {
				logger.debug(new FedExLogEntry("Failed to delete temp directory"));
			}
			throw e;
		}
		tokenTester(clientID);
		return tempDirLoc;
	}

	public static void tokenTester(String clientID)
			throws Exception {
		String token = "";
		try {
			token = createTestToken(prependApp(clientID), "943415_cds");
		}
		catch (SecurityConfigurationException sce) {
			logger.error(new FedExLogEntry("Caught SecurityConfigurationException: " + sce.getCause() + " " + sce.getMessage()));
			throw sce;
		}
		catch (Exception e) {
			logger.error(new FedExLogEntry("Caught General Exception e: " + e.getMessage()));
			throw e;
		}
		try {
			ServerCipherProviderFactory.configure(LdapCipherProviderImpl.getInstance());
			RevocationProviderFactory.configure(LdapCipherProviderImpl.getInstance());
			String principal = PkcTokenAuthenticatorImpl.getInstance().authenticate(token, "943415_cds").getName();
			if (principal.length() > 0) {
				logger.info(new FedExLogEntry("The Security API successfully validated the new certificate and  passphrase against LDAP"));
			}
		}
		catch (AuthenticationFailureException e) {
			System.err.println(e.getReasonCode() + " : " + e.getMessage());
			logger.error(new FedExLogEntry("Caught AuthenticationFailureException: " + e.getMessage()));
			throw e;
		}
	}

	private static String prependApp(String clientId) {
		String ret = "";
		if ((clientId == null) || (clientId.trim().equals(""))) {
			ret = "BAD";
		}
		if (clientId.matches("^APP[0-9]*[1-9][0-9]*$")) {
			ret = clientId;
		}
		else {
			if (clientId.matches("^[0-9]*[1-9][0-9]*$")) {
				ret = "APP" + clientId;
			}
		}
		return ret;
	}

	private static String decryptPassword(KeystoreStanza keystoreData) {
		try {
			Properties clientprops = FileLoader.getFileAsProperties(absolutePathOfClientFile);
			SecurityUtils.trimProperties(clientprops);
			String oldPasswd = clientprops.getProperty("client.keystore.password");
			String newPasswd = CryptoUtils.pbd(oldPasswd, keystoreData.getPassphrase());
			logger.debug(new FedExLogEntry(" The Security API successfully decrypted the new passphrase from CDS"));
			return newPasswd.trim();
		}
		catch (Exception e) {
			logger.error(new FedExLogEntry("Failed to decrypt the new passphrase. : " + e.getMessage()));
			throw new RuntimeException(e);
		}
	}

	private static void decodeCert(KeystoreStanza keystoreData) {
		String outFile = "output.dat";
		String tempDirLocation = createTempDir();
		File outputDat = new File(tempDirLocation + File.separatorChar + outFile);
		if (!StringUtils.isNullOrBlank(tempDirLocation)) {
			try {
				FileWriter fstream = new FileWriter(outputDat.getAbsolutePath());
				BufferedWriter br = new BufferedWriter(fstream);
				br.write(keystoreData.getKeystore());
				br.close();
				byte[] pkcs12 = Base64.decodeFromFile(outputDat.getAbsolutePath());
				FileUtil.putBytesToFile(tempDirLocation + fileName, pkcs12);
				if (!outputDat.delete()) {
					logger.debug("Unable to delete " + outputDat.getAbsolutePath());
				}
				logger.debug(new FedExLogEntry(" The Security API successfully decoded the cert from CDS"));
			}
			catch (Exception e) {
				logger.error(new FedExLogEntry("Failed to decode the new keystore : " + e.getMessage()));
				if ((outputDat != null) && (outputDat.exists())) {
					outputDat.delete();
				}
				try {
					if (FileUtil.deleteDir(new File(tempDirLocation))) {
						logger.debug(new FedExLogEntry(" Decoding of the cert failed so cleaning up the temp directory: " + tempDirLocation));
					}
				}
				catch (Exception ex) {
					logger.debug(new FedExLogEntry(" Failed to delete the temp directory ."));
				}
				throw new RuntimeException(e);
			}
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
		logger.fatal(new FedExLogEntry("Unable to determine application id from app.id in the fp.properties file, security policy is not available."));
		throw new SecurityConfigurationException("Unable to determine application id (check app.id), unable to retrieve security policy!");
	}

	public static Date getCDSCertExpirationDate() {
		Date certExpirationDate = null;
		try {
			KeystoreStanza keystoreData = getKeystoreFromCDS(getClientIdFromFingerPrint());
			if (keystoreData == null) {
				return certExpirationDate;
			}
			XMLGregorianCalendar xmlGregorianCalendar = keystoreData.getExpirationDateTime();
			certExpirationDate = xmlGregorianCalendar.toGregorianCalendar().getTime();
			logger.info(new FedExLogEntry(" New Cert Expiration Date from CDS ------- " + certExpirationDate));
			return certExpirationDate;
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Failed to get the expiration date of the new cert from CDS. : " + e.getMessage()));
			throw new RuntimeException(e);
		}
	}

	private static String createTempDir() {
		File tempDir = null;
		try {
			File ClientPropertiesPath = new File(absolutePathOfClientFile);
			File defaultDir = new File(ClientPropertiesPath.getParent());
			tempDir = new File(defaultDir.getAbsolutePath() + File.separator + "temp");
			if (tempDir.exists()) {
				return tempDir.getAbsolutePath() + File.separator;
			}
			boolean tempDirCreated = tempDir.mkdir();
			if (tempDirCreated) {
				if (tempDir.canWrite()) {
					logger.debug(new FedExLogEntry("The Security API is able to write to the following directory: " + tempDir.getAbsolutePath()));
					return tempDir.getAbsolutePath() + File.separator;
				}
				logger.error(new FedExLogEntry("The Security API is unable to write to the following directory: " + tempDir.getAbsolutePath()));
				return "";
			}
			logger.warn(new FedExLogEntry("The Security API is unable to create the following  temp directory: " + tempDir.getAbsolutePath()));
			return "";
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Exception: The Security API is unable to create the following  temp directory: " + tempDir.getAbsolutePath()));
			throw new RuntimeException(e);
		}
	}

	public static boolean configureCDSKeyStore(String backupCert, String backupClientProps)
			throws Exception {
		boolean configured = false;
		boolean cipherConfigured = false;
		boolean tokenGenConfigured = false;
		Properties newClientProps = FileLoader.getFileAsProperties(absolutePathOfClientFile);
		try {
			KeystoreCipherProviderImpl.getInstance().configure("APP" + getClientIdFromFingerPrint(), newClientProps, true);
			cipherConfigured = true;
			logger.debug(new FedExLogEntry("Configured KeystoreCipherProviderImpl with new client properties file: "));
		}
		catch (Exception KeystoreCipherConfigureError) {
			logger.error(new FedExLogEntry("CertRotation failed to reconfigure KeystoreCipherProviderImpl"));
			FileUtil.copy(backupCert, absolutePathOfCert);
			logger.debug(new FedExLogEntry("Rollback Restored " + backupCert + " to " + absolutePathOfCert));
			FileUtil.copy(backupClientProps, absolutePathOfClientFile);
			logger.debug(new FedExLogEntry("Rollback Restored " + backupClientProps + " to " + absolutePathOfClientFile));
			Properties clientProps = FileLoader.getFileAsProperties(absolutePathOfClientFile);
			try {
				KeystoreCipherProviderImpl.getInstance().configure("APP" + getClientIdFromFingerPrint(), clientProps, true);
				logger.debug(new FedExLogEntry("Configured KeystoreCipherProviderImpl with the original client properties file: " + absolutePathOfClientFile));
			}
			catch (Exception KeystoreCipherReConfigureError) {
				logger.error(new FedExLogEntry("Failed to Configured KeystoreCipherProviderImpl with the original client properties file so quitting"));
				logger.error(new FedExLogEntry("A manual restart is required at this point"));
			}
			throw KeystoreCipherConfigureError;
		}
		try {
			PkcTokenGeneratorImpl.getInstance().configure("APP" + getClientIdFromFingerPrint(), absolutePathOfClientFile);
			tokenGenConfigured = true;
			logger.debug(new FedExLogEntry("PkcTokenGeneratorImpl configured with  " + absolutePathOfClientFile));
		}
		catch (Exception PkcTokenGenConfigError) {
			logger.error(new FedExLogEntry("CertRotation failed to reconfigure PkcTokenGeneratorImpl"));
			FileUtil.copy(backupCert, absolutePathOfCert);
			logger.debug(new FedExLogEntry("Rollback Restored " + backupCert + " to " + absolutePathOfCert));
			FileUtil.copy(backupClientProps, absolutePathOfClientFile);
			logger.debug(new FedExLogEntry("Rollback Restored " + backupClientProps + " to " + absolutePathOfClientFile));
			newClientProps = FileLoader.getFileAsProperties(absolutePathOfClientFile);
			try {
				KeystoreCipherProviderImpl.getInstance().configure("APP" + getClientIdFromFingerPrint(), newClientProps, true);
				PkcTokenGeneratorImpl.getInstance().configure("APP" + getClientIdFromFingerPrint(), absolutePathOfClientFile);
				cipherConfigured = true;
				tokenGenConfigured = true;
			}
			catch (Exception KeystoreCipherConfigureError) {
				logger.error(new FedExLogEntry("Failed to Configured KeystoreCipherProviderImpl and PkcTokenGeneratorImpl with the original client properties file so quitting"));
				logger.error(new FedExLogEntry("A manual restart is required at this point"));
			}
			logger.debug(new FedExLogEntry("Rollback KeystoreCipherProviderImpl reconfigured with  " + newClientProps));
			logger.debug(new FedExLogEntry("Rollback PkcTokenGeneratorImpl reconfigured with  " + newClientProps));
			throw PkcTokenGenConfigError;
		}
		if ((cipherConfigured) && (tokenGenConfigured)) {
			configured = true;
		}
		return configured;
	}

	public static boolean rotateCert()
			throws Exception {
		boolean certRotated = false;
		String backupCert = "";
		String updatedCert = "";
		String backupClientProps = "";
		String newClientPropFile = "";
		String tempPath = "";
		try {
			tempPath = validateCDSCert(getClientIdFromFingerPrint());
			if (StringUtils.isNullOrBlank(tempPath)) {
				logger.warn(new FedExLogEntry("validateCDSCert was unable to determine the temp path."));
				return certRotated;
			}
			if (!tempPath.endsWith(File.separator)) {
				tempPath = tempPath.concat(File.separator);
			}
			File tempDir = new File(absolutePathOfClientFile);
			File backupDir = new File(tempDir.getParent());
			backupCert = backupDir + File.separator + fileName + ".bak";
			backupClientProps = backupDir + File.separator + "client.properties" + ".bak";
			updatedCert = tempPath + fileName;
			newClientPropFile = tempPath + "client.properties";
		}
		catch (Exception failedPathValidation) {
			logger.error(new FedExLogEntry("Caught General Exception e: " + failedPathValidation.getMessage()));
			throw new Exception("The Security API could not automatically rotate the cert because it failed validation. " + failedPathValidation.getMessage());
		}
		try {
			FileUtil.copy(absolutePathOfCert, backupCert);
			logger.debug(new FedExLogEntry("Copied " + absolutePathOfCert + " to " + backupCert));
			FileUtil.copy(absolutePathOfClientFile, backupClientProps);
			logger.debug(new FedExLogEntry("Copied " + absolutePathOfClientFile + " to " + backupClientProps));
		}
		catch (Exception failedBackup) {
			logger.warn(new FedExLogEntry("Failed to copy " + updatedCert + " to " + absolutePathOfCert));
			throw failedBackup;
		}
		synchronized (absolutePathOfClientFile) {
			try {
				FileUtil.copy(updatedCert, absolutePathOfCert);
				logger.warn(new FedExLogEntry("Copied " + updatedCert + " to " + absolutePathOfCert));
			}
			catch (Exception failedCopyCert) {
				logger.warn(new FedExLogEntry("Failed to copy " + updatedCert + " to " + absolutePathOfCert));
				throw failedCopyCert;
			}
			try {
				FileUtil.copy(newClientPropFile, absolutePathOfClientFile);
				logger.debug(new FedExLogEntry("Copied Props " + newClientPropFile + " to " + absolutePathOfClientFile));
			}
			catch (Exception failedCopyProps) {
				logger.warn(new FedExLogEntry("Failed to copy " + newClientPropFile + " to " + absolutePathOfClientFile));
				FileUtil.copy(backupCert, absolutePathOfCert);
				logger.debug(new FedExLogEntry("Rollback Restored " + backupCert + " to " + absolutePathOfCert));
				throw failedCopyProps;
			}
			if (configureCDSKeyStore(backupCert, backupClientProps)) {
				certRotated = true;
			}
		}
		if (FileUtil.deleteDir(new File(tempPath))) {
			logger.debug(new FedExLogEntry("Cleanup is removing temp directory: " + tempPath));
		}
		else {
			logger.warn(new FedExLogEntry("Failed to cleanup temp cert rotation files.  Could not delete directory " + tempPath));
		}
		return certRotated;
	}

	public static IndexQueryResponse indexQuery(List<IndexElementType> indexElements, StanzaIdType stanzaId, StanzaIdType indexStanzaId) {
		IndexQueryResponse queryResponse = new IndexQueryResponse();
		try {
			IndexQueryRequest request = objectFactory.createIndexQueryRequest();
			List<IndexQueryRequest.QueryItem> queryItems = request.getQueryItem();
			IndexQueryRequest.QueryItem queryItem = objectFactory.createIndexQueryRequestQueryItem();
			List<StanzaIdType> stanzaIds = queryItem.getStanzaId();
			stanzaIds.add(stanzaId);
			IndexQueryRequest.QueryItem.Index index = objectFactory.createIndexQueryRequestQueryItemIndex();
			index.setStanzaId(indexStanzaId);
			List<IndexElementType> indexIndexElements = index.getIndexElement();
			indexIndexElements.addAll(indexElements);
			queryItem.getIndex().add(index);
			PagingRequestType paging = objectFactory.createPagingRequestType();
			paging.setResultsPerPage(40);
			queryItem.setPaging(paging);
			queryItems.add(queryItem);
			IndexQueryResponse partialResponse = port.indexQuery(request);
			if (partialResponse == null) {
				return null;
			}
			List<IndexQueryResponse.QueryItem> queryItemList = partialResponse.getQueryItem();
			queryResponse.getQueryItem().addAll(queryItemList);
		}
		catch (SOAPFaultException e) {
			logger.warn(new FedExLogEntry("KeystoreClient: Caught SOAPFaultException e: " + e.toString()));
			logger.warn(new FedExLogEntry("code: " + e.getFault().getElementsByTagName("code").item(0).getTextContent()));
			logger.warn(new FedExLogEntry("desc: " + e.getFault().getElementsByTagName("desc").item(0).getTextContent()));
			throw new RuntimeException(e);
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
		return queryResponse;
	}

	public static String createTestToken(String clientId, String serviceName) {
		try {
			long createTimestamp = System.currentTimeMillis();
			Cipher cipher = ClientCipherProviderFactory.getProvider().getEncryptionCipher(clientId);
			String cipherText = "";
			byte[] cipherBytes = cipher.doFinal((serviceName + ":" + createTimestamp).getBytes(StandardCharsets.UTF_8));
			cipherText = new BASE64Encoder().encode(cipherBytes);
			logger.debug(new FedExLogEntry("Generated new token, clientId = " + clientId, " serviceName=" + serviceName));
			return "v1:" + clientId + ":" + cipherText + ":" + clientId;
		}
		catch (Exception e) {
			String msg = "Exception building cipher text for client " + clientId + ", service " + serviceName;
			logger.error(new FedExLogEntry(msg));
			throw new RuntimeException(msg, e);
		}
	}

	public static String getCdsUrl() {
		return cdsUrl;
	}

	public static void setCdsUrl(String cdsUrl) {
		cdsUrl = cdsUrl;
	}

	public static boolean reloadCertFromDisk() throws Exception {
		logger.debug(new FedExLogEntry("Inside reload cert from disk"));
		if (validateCert()) {
			Properties newClientProps = null;
			try {
				newClientProps = FileLoader.getFileAsProperties(absolutePathOfClientFile);
				SecurityUtils.trimProperties(newClientProps);
			}
			catch (RuntimeException re) {
				FileLoader.alwaysLogFiles(absolutePathOfClientFile);
				String msg = "Could not load the clientProperties file '" + absolutePathOfClientFile + "'.  Please verify the file exists at the absolute location or in the classpath.";
				logger.fatal(msg);
				throw new Exception(msg, re);
			}
			try {
				KeystoreCipherProviderImpl.getInstance().configure("APP" + getClientIdFromFingerPrint(), newClientProps, true);
				logger.debug(new FedExLogEntry("Configured KeystoreCipherProviderImpl with new client properties file: "));
			}
			catch (Exception KeystoreCipherConfigureError) {
				logger.error(new FedExLogEntry("Reload cert failed to reconfigure KeystoreCipherProviderImpl"));
				throw KeystoreCipherConfigureError;
			}
			try {
				PkcTokenGeneratorImpl.getInstance().configure("APP" + getClientIdFromFingerPrint(), absolutePathOfClientFile);
				logger.debug(new FedExLogEntry("PkcTokenGeneratorImpl configured with  " + absolutePathOfClientFile));
			}
			catch (Exception PkcTokenGenConfigError) {
				logger.error(new FedExLogEntry("CertRotation failed to reconfigure PkcTokenGeneratorImpl"));
				throw PkcTokenGenConfigError;
			}
		}
		return true;
	}

	public static boolean validateCert() {
		TokenGenerator gen = PkcTokenGeneratorImpl.getInstance();
		gen.configure(absolutePathOfClientFile);
		String token = "";
		boolean flag = false;
		try {
			token = gen.getToken("943415_cds");
		}
		catch (SecurityConfigurationException sce) {
			logger.error(new FedExLogEntry("Caught SecurityConfigurationException: " + sce.getCause() + " " + sce.getMessage()));
			throw sce;
		}
		catch (Exception e) {
			logger.error(new FedExLogEntry("Caught General Exception e: " + e.getMessage()));
		}
		try {
			ServerCipherProviderFactory.configure(LdapCipherProviderImpl.getInstance());
			RevocationProviderFactory.configure(LdapCipherProviderImpl.getInstance());
			String principal = PkcTokenAuthenticatorImpl.getInstance().authenticate(token, "943415_cds").getName();
			if (principal.length() > 0) {
				logger.info(new FedExLogEntry("The Security API successfully validated the new certificate and  passphrase against LDAP"));
				flag = true;
			}
		}
		catch (AuthenticationFailureException e) {
			logger.error(new FedExLogEntry("Caught AuthenticationFailureException: " + e.getMessage()));
		}
		catch (Exception e) {
		}
		return flag;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\client\KeystoreRotation.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */