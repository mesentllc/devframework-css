package com.fedex.security.server;

import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import com.fedex.framework.utility.FedExAppFrameworkProperties;
import com.fedex.idm.delegation.webservice.AssignmentReturnVO;
import com.fedex.idm.delegation.webservice.DelegationPortType;
import com.fedex.idm.delegation.webservice.DelegationV2;
import com.fedex.security.common.FileLoader;

import javax.xml.namespace.QName;
import javax.xml.ws.WebServiceException;
import java.io.File;
import java.io.Serializable;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public final class IDM
		implements Serializable {
	private static final long serialVersionUID = 1L;
	private static String LOCAL_CACHE_DIR = "";
	private static final String idmFunctionName = "FUNCTION";
	private static final String idmDelegator = "DELEGATOR";
	private static final String idmDelegate = "DELEGATE";
	private static String clientName = "";
	private static String clientId = "";
	private static String idmURL = "";
	private static String cacheFileName = "IDM.cache";
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(IDM.class.getName());
	public static List<IDMCacheObject> idmList = new ArrayList();
	public static final FileLoader localLoader = new FileLoader();
	public static DelegationPortType delegation = null;
	public static DelegationV2 service;
	public static boolean idmCheck = false;

	public IDM(String idmUrl, String localCacheDir) {
		clientName = FedExAppFrameworkProperties.getInstance().getSymphonyName();
		clientId = FedExAppFrameworkProperties.getInstance().getAppId();
		if ((idmUrl == null) || (idmUrl.isEmpty())) {
			logger.info("No IDM URL passed to IDM class");
		}
		else {
			idmURL = idmUrl;
			LOCAL_CACHE_DIR = localCacheDir;
			try {
				service = new DelegationV2(new URL(idmURL), new QName("http://delegationv2.idm.fedex.com/", "DelegationV2"));
			}
			catch (WebServiceException e) {
				logger.warn(" Cannot access the IDM web service with the given IDM URL" + idmURL);
			}
			catch (Exception e) {
				logger.warn(" Cannot access the IDM web service with the given IDM URL" + idmURL);
			}
		}
	}

	public void writeIDMCacheToDisk(List<IDMCacheObject> idmList) {
		try {
			logger.info(new FedExLogEntry("Writing IDM cache to disk : " + idmList.size()));
			localLoader.saveObjectToDisk(LOCAL_CACHE_DIR + File.separator + cacheFileName, idmList);
			logger.info(new FedExLogEntry("IDM cache written to disk at location: " + cacheFileName));
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("[IDMCache]F attempting to write IDM cache to disk: " + e));
		}
	}

	private static void readIDMCacheFromDisk() {
		try {
			logger.info(new FedExLogEntry("Reading IDM cache"));
			Object fromDisk = localLoader.readObjectFromDisk(LOCAL_CACHE_DIR + File.separator + cacheFileName);
			if ((fromDisk != null) && ((fromDisk instanceof List))) {
				List<IDMCacheObject> policyCacheFromDisk = (List)fromDisk;
				policyCacheFromDisk.addAll((List)fromDisk);
				idmList.addAll(policyCacheFromDisk);
				logger.info(new FedExLogEntry("[IDM]Successfully loaded idm cache from disk."));
			}
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("[IDMCache]Failed attempting to read IDM cache from disk: " + e));
		}
	}

	public static String evaluateIDMCache(String uid, String resource, String action) {
		readIDMCacheFromDisk();
		String function_name = resource.concat(":").concat(action);
		logger.info(new FedExLogEntry("function_name: " + function_name + " uid: " + uid));
		String delegator = "";
		for (IDMCacheObject localObject : idmList) {
			if ((localObject.getCache_functionName().equals(function_name)) && (localObject.getCache_delegate().equals(uid))) {
				logger.info(new FedExLogEntry("Idm function name: " + localObject.toString()));
				delegator = localObject.getCache_delegator();
				return delegator;
			}
		}
		return delegator;
	}

	public void queryIDMWebService() {
		try {
			logger.info(new FedExLogEntry("Querying IDM for assignments... "));
			delegation = service.getDelegationPortTypePort();
			idmList = new ArrayList();
			List<AssignmentReturnVO> assignments = delegation.getAssignmentsForAppID(getClientIdFromFingerPrint(), "");
			if ((assignments != null) && (!assignments.isEmpty())) {
				for (AssignmentReturnVO assignment : assignments) {
					IDMCacheObject idmCacheObj = new IDMCacheObject();
					if (assignment.getFunction() != null) {
						idmCacheObj.setCache_functionName(assignment.getFunction());
						if (assignment.getDelegator() != null) {
							idmCacheObj.setCache_delegator(assignment.getDelegator());
							if (assignment.getDelegate() != null) {
								idmCacheObj.setCache_delegate(assignment.getDelegate());
								logger.debug(new FedExLogEntry("idmCacheObj: " + idmCacheObj.toString()));
								idmList.add(idmCacheObj);
							}
						}
					}
				}
			}
			writeIDMCacheToDisk(idmList);
			idmList.clear();
		}
		catch (Exception exc) {
			logger.warn("Unable to query IDM: " + exc.toString());
		}
	}

	private final class IDMCacheObject implements Serializable {
		private static final long serialVersionUID = 1L;

		private IDMCacheObject() {
		}

		public String cache_functionName = "";
		public String cache_delegator = "";
		public String cache_delegate = "";

		public String getCache_functionName() {
			return this.cache_functionName;
		}

		public void setCache_functionName(String cacheFunctionName) {
			this.cache_functionName = cacheFunctionName;
		}

		public String getCache_delegator() {
			return this.cache_delegator;
		}

		public void setCache_delegator(String cacheDelegator) {
			this.cache_delegator = cacheDelegator;
		}

		public String getCache_delegate() {
			return this.cache_delegate;
		}

		public void setCache_delegate(String cacheDelegate) {
			this.cache_delegate = cacheDelegate;
		}

		public String toString() {
			return "function_name: " + this.cache_functionName + ", delegator: " + this.cache_delegator + ", delegate: " + this.cache_delegate;
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
		logger.warn(new FedExLogEntry("Unable to determine application id from app.id in the fp.properties file, idm delegation is not available."));
		return clientId;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\server\IDM.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */