package com.fedex.cds;

import com.fedex.common.icefaces.util.FacesUtils;
import com.fedex.ea.framework.securityapi.dao.esc.EscDaoException;
import com.fedex.enterprise.security.cds.authZ.AuditRecord;
import com.fedex.enterprise.security.cds.authZ.CustomAuthZClass;
import com.fedex.enterprise.security.customauthz.CustomAuthzData;
import com.fedex.enterprise.security.customauthz.CustomAuthzService;
import com.fedex.enterprise.security.esc.view.model.WssoHandler;
import com.fedex.enterprise.security.utils.EscUtils;
import com.fedex.enterprise.security.utils.SecurityDataBaseClass;
import com.fedex.framework.cds.IndexElementType;
import com.fedex.framework.cds.IndexQueryResponse;
import com.fedex.framework.cds.InsertRequest;
import com.fedex.framework.cds.KeyQueryRequest;
import com.fedex.framework.cds.KeyQueryResponse;
import com.fedex.framework.cds.KeyedStanzasType;
import com.fedex.framework.cds.StanzaIdType;
import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import org.springframework.ws.soap.client.SoapFaultClientException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.ws.soap.SOAPFaultException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

public class CdsSecurityCustomAuthorizer
		extends CdsSecurityBase
		implements CustomAuthzService {
	private static final String EMPTY_VALUE = null;
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(CdsSecurityCustomAuthorizer.class);

	public void deleteCustomAuthz(CustomAuthzData customAuthz) {
		deleteCustomAuthz(customAuthz, false);
	}

	public static void deleteCustomAuthz(CustomAuthzData customAuthz, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		try {
			if (!systemOverride) {
				WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
				onBehalfOf = roleHandler.getUserId();
			}
		}
		catch (SOAPFaultException sfe) {
			throw new RuntimeException(sfe.getMessage(), sfe);
		}
		deleteCustomAuthz(customAuthz, systemOverride, onBehalfOf, "");
	}

	public static void deleteCustomAuthz(CustomAuthzData customAuthz, boolean systemOverride, String onBehalfOf, String appId) {
		String callingApp = "";
		try {
			if (EscUtils.isNullOrBlank(appId)) {
				callingApp = "4112";
			}
			else {
				callingApp = appId;
			}
			String desc = customAuthz.getClassNm() + " was deleted by " + onBehalfOf + " from " + (callingApp.equals("4112") ? "the ESC." : new StringBuilder().append("App #").append(callingApp).toString());
			InsertRequest.InsertItem auditRecord = createStaticAuditRecord(callingApp, onBehalfOf, desc, "delete", "customAuthZClass");
			Delete(Long.valueOf(customAuthz.getDocId()), "customAuthZClass", auditRecord, systemOverride);
		}
		catch (SecurityException se) {
			throw new RuntimeException(se.getMessage(), se);
		}
	}

	public long insertCustomAuthz(CustomAuthzData customAuthz) {
		return insertCustomAuthz(customAuthz, false);
	}

	public static long insertCustomAuthz(CustomAuthzData customAuthz, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		try {
			if (!systemOverride) {
				WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
				onBehalfOf = roleHandler.getUserId();
			}
		}
		catch (SOAPFaultException sfe) {
			throw new RuntimeException(sfe.getMessage(), sfe);
		}
		return insertCustomAuthz(customAuthz, systemOverride, onBehalfOf, "");
	}

	public static long insertCustomAuthz(CustomAuthzData customAuthz, boolean systemOverride, String onBehalfOf, String appId) {
		List<Document> request = new ArrayList();
		String callingApp = "";
		try {
			if (EscUtils.isNullOrBlank(appId)) {
				callingApp = "4112";
			}
			else {
				callingApp = appId;
			}
			com.fedex.enterprise.security.cds.authZ.ObjectFactory securityObjectFactory = new com.fedex.enterprise.security.cds.authZ.ObjectFactory();
			JAXBContext propJaxbContext = JAXBContext.newInstance("com.fedex.enterprise.security.cds.authZ");
			Marshaller propMarshaller = propJaxbContext.createMarshaller();
			CustomAuthZClass customAuthzClass = securityObjectFactory.createCustomAuthZClass();
			String description = customAuthz.getClassDesc();
			if ((description == null) || (description.isEmpty())) {
				description = "NA";
			}
			customAuthzClass.setCustomAuthZClassDesc(customAuthz.getClassDesc());
			customAuthzClass.setCustomAuthZClassName(customAuthz.getClassNm());
			customAuthzClass.setDomain("authZ");
			customAuthzClass.setMajorVersion(STANZA_DESC_MAJOR_VER);
			customAuthzClass.setMinorVersion(STANZA_DESC_MINOR_VER);
			customAuthzClass.setApplicationId(Long.parseLong(customAuthz.getAppId()));
			Document doc = BuildDocument();
			propMarshaller.marshal(customAuthzClass, doc);
			request.add(doc);
			String desc = customAuthz.getClassNm() + " was created by " + onBehalfOf + " from " + (callingApp.equals("4112") ? "the ESC." : new StringBuilder().append("App #").append(callingApp).toString());
			AuditRecord auditRecord = createStaticAuditRecordObject(customAuthz.getAppId() + "", onBehalfOf, desc, "create", "customAuthZClass");
			List<InsertRequest.InsertItem> auditRecords = new ArrayList();
			CdsSecurityAuditReport.Insert(auditRecord, true);
			List<Long> keys = cdsClient.insert(request, auditRecords, systemOverride);
			customAuthz.setDocId(keys.get(0).longValue());
			return keys.get(0).longValue();
		}
		catch (SoapFaultClientException sfx) {
			throw sfx;
		}
		catch (JAXBException jbEx) {
			logger.warn(new FedExLogEntry("Caught JAXB Exception ex: " + jbEx.toString()));
			throw new RuntimeException(jbEx.toString(), jbEx);
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Caught general Exception ex: " + e.toString()));
			throw new RuntimeException(e.getMessage(), e);
		}
	}

	public void updateCustomAuthz(CustomAuthzData customAuthz) {
		updateCustomAuthz(customAuthz, false);
	}

	public static void updateCustomAuthz(CustomAuthzData customAuthz, boolean systemOverride) {
		WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
		String onBehalfOf = "APP4112";
		if (!systemOverride) {
			onBehalfOf = roleHandler.getUserId();
		}
		updateCustomAuthz(customAuthz, systemOverride, onBehalfOf, "");
	}

	public static void updateCustomAuthz(CustomAuthzData customAuthz, boolean systemOverride, String onBehalfOf, String appId) {
		String callingApp = "";
		if (EscUtils.isNullOrBlank(appId)) {
			callingApp = "4112";
		}
		else {
			callingApp = appId;
		}
		HashMap<String, String> xpathList = new HashMap();
		String description = customAuthz.getClassDesc();
		if ((description == null) || (description.isEmpty())) {
			description = "NA";
		}
		xpathList.put("/customAuthZClass/@CustomAuthZClassDesc", description);
		xpathList.put("/customAuthZClass/@CustomAuthZClassName", customAuthz.getClassNm());
		String desc = customAuthz.getClassNm() + " was modified by " + onBehalfOf + " from " + (callingApp.equals("4112") ? "the ESC." : new StringBuilder().append("App #").append(callingApp).toString());
		InsertRequest.InsertItem auditRecord = createStaticAuditRecord(customAuthz.getAppId(), onBehalfOf, desc, "modify", "customAuthZClass");
		cdsClient.update(xpathList, customAuthz.getDocId(), "authZ", "customAuthZClass", auditRecord, systemOverride);
	}

	private static List<IndexElementType> BuildIndexQuery(int appID, String partialCustomAuthzName) {
		List<IndexElementType> indexElements = new ArrayList();
		IndexElementType appId = new IndexElementType();
		appId.setXpath("/customAuthZClass/@ApplicationId");
		appId.setComparison("equals");
		appId.setValue(Integer.toString(appID));
		indexElements.add(appId);
		if (null != partialCustomAuthzName) {
			IndexElementType customAuthzName = new IndexElementType();
			customAuthzName.setXpath("/customAuthZClass/@CustomAuthZClassName");
			customAuthzName.setComparison("equals");
			customAuthzName.setValue(partialCustomAuthzName);
			indexElements.add(customAuthzName);
		}
		return indexElements;
	}

	public static List<CustomAuthzData> retrieve(List<Long> keys, boolean mapObjects) throws EscDaoException {
		return castList(cdsClient.keyQuery(keys, "authZ", CdsSecurityBase.STANZAS.customAuthZClass, mapObjects));
	}

	private static List<CustomAuthzData> castList(List<SecurityDataBaseClass> tempList) {
		List<CustomAuthzData> list = new ArrayList(tempList.size());
		for (SecurityDataBaseClass base : tempList) {
			list.add((CustomAuthzData)base);
		}
		return list;
	}

	public static List<CustomAuthzData> getCustomAuthzsForApplication(String appId) {
		String bookmark = "";
		List<CustomAuthzData> response = new ArrayList();
		int totalDocCount = 0;
		Bookmark bookmarkId = new Bookmark();
		bookmarkId.setBookmark("5120135");
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		StanzaIdType stanzaId = of.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("customAuthZClass");
		StanzaIdType indexStanzaId = of.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("customAuthZClass");
		Unmarshaller unmarshaller;
		do {
			IndexQueryResponse indexResponse = cdsClient.indexQuery(BuildIndexQuery(Integer.parseInt(appId), EMPTY_VALUE), stanzaId, indexStanzaId, bookmark);
			List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
			JAXBContext propertiesStanzaContext = null;
			unmarshaller = null;
			try {
				propertiesStanzaContext = JAXBContext.newInstance(CustomAuthZClass.class);
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in getCustomAuthzsForApplication new instance"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			try {
				unmarshaller = propertiesStanzaContext.createUnmarshaller();
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in getCustomAuthzsForApplication create unmarshaller"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
				for (Iterator i$ = queryItem.getKeyedStanzas().iterator(); i$.hasNext(); ) {
					KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
					totalDocCount++;
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						CustomAuthZClass currentCustomAuthZ = null;
						try {
							currentCustomAuthZ = (CustomAuthZClass)unmarshaller.unmarshal(docElement);
							CustomAuthzData customAuthz = new CustomAuthzData();
							customAuthz.setClassNm(currentCustomAuthZ.getCustomAuthZClassName());
							customAuthz.setClassDesc(currentCustomAuthZ.getCustomAuthZClassDesc());
							customAuthz.setAppId(String.valueOf(currentCustomAuthZ.getApplicationId()));
							customAuthz.setDocId(keyedStanzas.getKey());
							response.add(customAuthz);
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("Caught JAXBException in getCustomAuthzsForApplication unmarshal"), e);
						}
						continue;
					}
				}
				bookmark = queryItem.getPaging().getBookmark();
			}
		}
		while ((!"".equals(bookmark)) && (bookmarkId.getBookmark() == "5120135"));
		bookmarkId.setBookmark(bookmark);
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR CustomAuthorizer = " + totalDocCount));
		return response;
	}

	public CustomAuthzData getCustomAuthzByName(String appId, String customAuthzName) {
		String bookmark = "";
		int totalDocCount = 0;
		CustomAuthzData customAuthz = new CustomAuthzData();
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		Bookmark bookmarkId = new Bookmark();
		bookmarkId.setBookmark("5120135");
		StanzaIdType stanzaId = of.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("customAuthZClass");
		StanzaIdType indexStanzaId = of.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("customAuthZClass");
		Unmarshaller unmarshaller;
		do {
			IndexQueryResponse indexResponse = cdsClient.indexQuery(BuildIndexQuery(Integer.parseInt(appId), customAuthzName), stanzaId, indexStanzaId, bookmark);
			List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
			JAXBContext propertiesStanzaContext = null;
			unmarshaller = null;
			try {
				propertiesStanzaContext = JAXBContext.newInstance(CustomAuthZClass.class);
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in getCustomAuthzByName new instance"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			try {
				unmarshaller = propertiesStanzaContext.createUnmarshaller();
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in getCustomAuthzByName create unmarshaller"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
				for (Iterator i$ = queryItem.getKeyedStanzas().iterator(); i$.hasNext(); ) {
					KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
					totalDocCount++;
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						CustomAuthZClass currentCustomAuthZ = null;
						try {
							currentCustomAuthZ = (CustomAuthZClass)unmarshaller.unmarshal(docElement);
							customAuthz.setClassNm(currentCustomAuthZ.getCustomAuthZClassName());
							customAuthz.setClassDesc(currentCustomAuthZ.getCustomAuthZClassDesc());
							customAuthz.setAppId(String.valueOf(currentCustomAuthZ.getApplicationId()));
							customAuthz.setDocId(keyedStanzas.getKey());
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("Caught JAXBException in getCustomAuthzByName unmarshal"), e);
						}
						continue;
					}
				}
				bookmark = queryItem.getPaging().getBookmark();
			}
		}
		while ((!"".equals(bookmark)) && (bookmarkId.getBookmark() == "5120135"));
		bookmarkId.setBookmark(bookmark);
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR CustomAuthorizer = " + totalDocCount));
		return customAuthz;
	}

	public static CustomAuthzData getCustomAuthzByKey(Long docId) {
		Unmarshaller unmarshaller = null;
		JAXBContext propertiesStanzaContext = null;
		try {
			propertiesStanzaContext = JAXBContext.newInstance(CustomAuthZClass.class);
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in getCustomAuthzByKey new instance"), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		try {
			unmarshaller = propertiesStanzaContext.createUnmarshaller();
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in getCustomAuthzByKey create unmarshaller"), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		CustomAuthzData customAuthz = new CustomAuthzData();
		List<Long> keyList = new ArrayList();
		keyList.add(docId);
		KeyQueryRequest request = buildKeyQueryRequest(keyList, "customAuthZClass");
		KeyQueryResponse response = cdsClient.keyQuery(request);
		for (Iterator i$ = response.getKeyedStanzas().iterator(); i$.hasNext(); ) {
			KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
			List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
			for (KeyedStanzasType.Stanza s : stanzaList) {
				Element docElement = s.getAny();
				CustomAuthZClass currentCustomAuthZ = null;
				try {
					currentCustomAuthZ = (CustomAuthZClass)unmarshaller.unmarshal(docElement);
					customAuthz.setClassNm(currentCustomAuthZ.getCustomAuthZClassName());
					customAuthz.setClassDesc(currentCustomAuthZ.getCustomAuthZClassDesc());
					customAuthz.setAppId(String.valueOf(currentCustomAuthZ.getApplicationId()));
					customAuthz.setDocId(keyedStanzas.getKey());
				}
				catch (JAXBException e) {
					logger.error(new FedExLogEntry("Caught JAXBException in getCustomAuthzByKey unmarshal"), e);
				}
				continue;
			}
		}
		return customAuthz;
	}

	public List<CustomAuthzData> getCustomAuthzForApplication(String appId) {
		return getCustomAuthzsForApplication(appId);
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\cds\CdsSecurityCustomAuthorizer.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */