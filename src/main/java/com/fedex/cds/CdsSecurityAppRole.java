package com.fedex.cds;

import com.fedex.common.icefaces.util.FacesUtils;
import com.fedex.ea.framework.securityapi.dao.esc.EscDaoException;
import com.fedex.enterprise.security.cds.authZ.ApplicationRole;
import com.fedex.enterprise.security.esc.view.model.WssoHandler;
import com.fedex.enterprise.security.role.AppRoleData;
import com.fedex.enterprise.security.role.RoleData;
import com.fedex.enterprise.security.utils.EscUtils;
import com.fedex.enterprise.security.utils.LDAPUserRecord;
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
import com.fedex.security.common.StringUtils;
import org.springframework.ws.soap.client.SoapFaultClientException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class CdsSecurityAppRole
		extends CdsSecurityBase {
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(CdsSecurityAppRole.class);

	public static long Insert(AppRoleData appRoleData, long roleDocId) {
		return Insert(appRoleData, roleDocId, false);
	}

	public static long Insert(AppRoleData appRoleData, long roleDocId, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		if (!systemOverride) {
			WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
			onBehalfOf = roleHandler.getUserId();
		}
		return Insert(appRoleData, roleDocId, systemOverride, onBehalfOf, "");
	}

	public static long Insert(AppRoleData appRoleData, long roleDocId, boolean systemOverride, String onBehalfOf, String appId) {
		List<Document> request = new ArrayList();
		try {
			String callingApp = "4112";
			if (EscUtils.isNullOrBlank(appId)) {
				callingApp = "4112";
			}
			else {
				callingApp = appId;
			}
			RoleData role = CdsSecurityRole.Retrieve(roleDocId, false);
			com.fedex.enterprise.security.cds.authZ.ObjectFactory securityObjectFactory = new com.fedex.enterprise.security.cds.authZ.ObjectFactory();
			JAXBContext propJaxbContext = JAXBContext.newInstance("com.fedex.enterprise.security.cds.authZ");
			Marshaller propMarshaller = propJaxbContext.createMarshaller();
			ApplicationRole cdsApplicationRole = securityObjectFactory.createApplicationRole();
			cdsApplicationRole.setApplicationId(Long.parseLong(appRoleData.getAppId()));
			if (roleDocId != 0L) {
				cdsApplicationRole.setRoleDocId(roleDocId);
			}
			else {
				cdsApplicationRole.setRoleDocId(appRoleData.getRoleDocId());
			}
			if (!EscUtils.isNullOrBlank(onBehalfOf)) {
				cdsApplicationRole.setAssignedBy(onBehalfOf);
			}
			cdsApplicationRole.setDateAssigned(getStaticDateTime());
			cdsApplicationRole.setDomain("authZ");
			cdsApplicationRole.setMajorVersion(STANZA_DESC_MAJOR_VER);
			cdsApplicationRole.setMinorVersion(STANZA_DESC_MINOR_VER);
			Document doc = BuildDocument();
			propMarshaller.marshal(cdsApplicationRole, doc);
			request.add(doc);
			String desc = appRoleData.getAppId() + " was added to the " + role.getRoleNm() + " role by " + onBehalfOf + " from " + (callingApp.equals("4112") ? "the ESC." : new StringBuilder().append("App #").append(callingApp).toString());
			InsertRequest.InsertItem auditRecord = createStaticAuditRecord(role.getRoleScopeNm(), onBehalfOf, desc, "create", "applicationRole");
			List<InsertRequest.InsertItem> auditRecords = new ArrayList();
			auditRecords.add(auditRecord);
			List<Long> keys = cdsClient.insert(request, auditRecords, systemOverride);
			appRoleData.setDocId(keys.get(0).longValue());
		}
		catch (JAXBException jbEx) {
			logger.warn(new FedExLogEntry("Caught JAXB Exception ex: " + jbEx.toString()));
			throw new RuntimeException(jbEx.toString(), jbEx);
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Caught general Exception ex: " + e.toString()));
			throw new RuntimeException(e.getMessage(), e);
		}
		return appRoleData.getDocId();
	}

	public static long Insert(AppRoleData appRoleData, long roleDocId, String roleName, boolean systemOverride, String onBehalfOf, String appId) {
		List<Document> request = new ArrayList();
		try {
			String callingApp = "4112";
			if (EscUtils.isNullOrBlank(appId)) {
				callingApp = "4112";
			}
			else {
				callingApp = appId;
			}
			com.fedex.enterprise.security.cds.authZ.ObjectFactory securityObjectFactory = new com.fedex.enterprise.security.cds.authZ.ObjectFactory();
			JAXBContext propJaxbContext = JAXBContext.newInstance("com.fedex.enterprise.security.cds.authZ");
			Marshaller propMarshaller = propJaxbContext.createMarshaller();
			ApplicationRole cdsApplicationRole = securityObjectFactory.createApplicationRole();
			cdsApplicationRole.setApplicationId(Long.parseLong(appRoleData.getAppId()));
			if (roleDocId != 0L) {
				cdsApplicationRole.setRoleDocId(roleDocId);
			}
			else {
				cdsApplicationRole.setRoleDocId(appRoleData.getRoleDocId());
			}
			if (!EscUtils.isNullOrBlank(onBehalfOf)) {
				cdsApplicationRole.setAssignedBy(onBehalfOf);
			}
			cdsApplicationRole.setDateAssigned(getStaticDateTime());
			cdsApplicationRole.setDomain("authZ");
			cdsApplicationRole.setMajorVersion(STANZA_DESC_MAJOR_VER);
			cdsApplicationRole.setMinorVersion(STANZA_DESC_MINOR_VER);
			Document doc = BuildDocument();
			propMarshaller.marshal(cdsApplicationRole, doc);
			request.add(doc);
			String desc = appRoleData.getAppId() + " was added to the " + roleName + " role by " + onBehalfOf + " from " + (callingApp.equals("4112") ? "the ESC." : new StringBuilder().append("App #").append(callingApp).toString());
			InsertRequest.InsertItem auditRecord = createStaticAuditRecord(appId, onBehalfOf, desc, "create", "applicationRole");
			List<InsertRequest.InsertItem> auditRecords = new ArrayList();
			auditRecords.add(auditRecord);
			List<Long> keys = cdsClient.insert(request, auditRecords, systemOverride);
			appRoleData.setDocId(keys.get(0).longValue());
		}
		catch (JAXBException jbEx) {
			logger.warn(new FedExLogEntry("Caught JAXB Exception ex: " + jbEx.toString()));
			throw new RuntimeException(jbEx.toString(), jbEx);
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Caught general Exception ex: " + e.toString()));
			throw new RuntimeException(e.getMessage(), e);
		}
		return appRoleData.getDocId();
	}

	public static AppRoleData RetrieveByKey(long docId) {
		Unmarshaller unmarshaller = null;
		JAXBContext extRefStanzaContext = null;
		AppRoleData appRoleData = null;
		try {
			extRefStanzaContext = JAXBContext.newInstance(ApplicationRole.class);
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Error in the RetrieveByKey new instance"), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		try {
			unmarshaller = extRefStanzaContext.createUnmarshaller();
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Error in the RetrieveByKey create unmarshaller"), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		try {
			List<Long> keys = new ArrayList();
			keys.add(Long.valueOf(docId));
			KeyQueryRequest request = buildKeyQueryRequest(keys, "applicationRole");
			KeyQueryResponse response = cdsClient.keyQuery(request);
			for (Iterator i$ = response.getKeyedStanzas().iterator(); i$.hasNext(); ) {
				KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
				List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
				for (KeyedStanzasType.Stanza s : stanzaList) {
					Element docElement = s.getAny();
					ApplicationRole currentAppRole = null;
					try {
						currentAppRole = (ApplicationRole)unmarshaller.unmarshal(docElement);
						appRoleData = new AppRoleData();
						appRoleData.setApplicationName(currentAppRole.getApplicationId() + "");
						appRoleData.setRoleDocId(currentAppRole.getRoleDocId());
						appRoleData.setDocId(keyedStanzas.getKey());
					}
					catch (JAXBException e) {
						logger.error(new FedExLogEntry("Error in the RetrieveByKey unmarshal"), e);
					}
					continue;
				}
			}
		}
		catch (SoapFaultClientException sfx) {
			throw sfx;
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Caught general Exception ex: " + e.toString()));
			throw new RuntimeException(e);
		}
		return appRoleData;
	}

	public static List<AppRoleData> Retrieve(long roleKey) {
		return Retrieve(roleKey, null, true);
	}

	public static List<AppRoleData> Retrieve(String appId) {
		return Retrieve(0L, appId, true);
	}

	public static List<AppRoleData> Retrieve(long roleKey, boolean ldapAttribs) {
		return Retrieve(roleKey, null, ldapAttribs);
	}

	public static List<AppRoleData> Retrieve(String appId, boolean ldapAttribs) {
		return Retrieve(0L, appId, ldapAttribs);
	}

	public static List<AppRoleData> retrieveForRuleAppId(String ruleAppId, boolean mapObjects) throws EscDaoException {
		List<SecurityDataBaseClass> baseList = cdsClient.indexQuery("/rule/@ApplicationId", CdsClient.QUERY_COMPARE.equals, ruleAppId, "authZ", CdsSecurityBase.STANZAS.rule, "authZ", CdsSecurityBase.STANZAS.applicationRole, mapObjects);
		return castList(baseList);
	}

	public static List<AppRoleData> Retrieve(long roleKey, String appId, boolean ldapAttribs) {
		String bookmark = "";
		List<AppRoleData> response = new ArrayList();
		int totalDocCount = 0;
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		StanzaIdType stanzaId = of.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("applicationRole");
		StanzaIdType indexStanzaId = of.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("applicationRole");
		IndexQueryResponse indexResponse = null;
		Unmarshaller unmarshaller;
		do {
			indexResponse = cdsClient.indexQuery(BuildIndexQuery(roleKey, appId), stanzaId, indexStanzaId, bookmark);
			List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
			JAXBContext resourceStanzaContext = null;
			unmarshaller = null;
			try {
				resourceStanzaContext = JAXBContext.newInstance(ApplicationRole.class);
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Error in the Retrieve new instance"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			try {
				unmarshaller = resourceStanzaContext.createUnmarshaller();
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Error in the Retrieve create unmarshaller"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
				for (Iterator i$ = queryItem.getKeyedStanzas().iterator(); i$.hasNext(); ) {
					KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
					totalDocCount++;
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						ApplicationRole currentAppRole = null;
						try {
							currentAppRole = (ApplicationRole)unmarshaller.unmarshal(docElement);
							AppRoleData newAppRoleData = new AppRoleData();
							newAppRoleData.setDocId(keyedStanzas.getKey());
							newAppRoleData.setAppId(Long.toString(currentAppRole.getApplicationId()));
							newAppRoleData.setRoleDocId(currentAppRole.getRoleDocId());
							if (!StringUtils.isNullOrBlank(currentAppRole.getAssignedBy())) {
								newAppRoleData.setAssignedBy(currentAppRole.getAssignedBy());
							}
							if (currentAppRole.getDateAssigned() != null) {
								newAppRoleData.setDateAssigned(currentAppRole.getDateAssigned().toGregorianCalendar());
							}
							if (ldapAttribs) {
								LDAPUserRecord record = ldapSearch.getUserAttribs("APP" + newAppRoleData.getAppId());
								newAppRoleData.setApplicationName(record.getLastName());
							}
							response.add(newAppRoleData);
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("Error in the Retrieve unmarshal"), e);
						}
						continue;
					}
				}
				bookmark = queryItem.getPaging().getBookmark();
			}
		}
		while (!"".equals(bookmark));
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR APP MEMBERS = " + totalDocCount));
		return response;
	}

	private static List<IndexElementType> BuildIndexQuery(long roleDocID, String appId) {
		List<IndexElementType> indexElements = new ArrayList();
		if (roleDocID != 0L) {
			IndexElementType docId = new IndexElementType();
			docId.setXpath("/applicationRole/@RoleDocId");
			docId.setComparison("equals");
			docId.setValue(Long.toString(roleDocID));
			indexElements.add(docId);
		}
		if ((appId != null) && (!appId.isEmpty())) {
			IndexElementType userId = new IndexElementType();
			userId.setXpath("/applicationRole/@ApplicationId");
			userId.setComparison("equals");
			userId.setValue(appId);
			indexElements.add(userId);
		}
		return indexElements;
	}

	private static List<AppRoleData> castList(List<SecurityDataBaseClass> tempList) {
		List<AppRoleData> list = new ArrayList(tempList.size());
		for (SecurityDataBaseClass base : tempList) {
			list.add((AppRoleData)base);
		}
		return list;
	}

	public static List<AppRoleData> getRoleDataAppInfo(long roleKey)
			throws EscDaoException {
		List<SecurityDataBaseClass> dataList = cdsClient.indexQuery("/applicationRole/@RoleDocId", CdsClient.QUERY_COMPARE.equals, Long.toString(roleKey), "authZ", CdsSecurityBase.STANZAS.applicationRole, "authZ", CdsSecurityBase.STANZAS.applicationRole, true);
		return castList(dataList);
	}

	public static AppRoleData processAppRoleStanza(long docId, KeyedStanzasType.Stanza appStanza) {
		ApplicationRole applicationRole = null;
		AppRoleData appRoleData = null;
		try {
			Element docElement = appStanza.getAny();
			applicationRole = (ApplicationRole)cdsAuthZUnmarshaller.unmarshal(docElement);
			if (applicationRole != null) {
				appRoleData = new AppRoleData();
				appRoleData.setDocId(docId);
				appRoleData.setAppId(Long.toString(applicationRole.getApplicationId()));
				appRoleData.setRoleDocId(applicationRole.getRoleDocId());
				appRoleData.setAssignedBy(applicationRole.getAssignedBy());
				appRoleData.setDateAssigned(applicationRole.getDateAssigned().toGregorianCalendar());
			}
			else {
				logger.info(new FedExLogEntry("Application Role is null after unmarshalling Stanza for DocId " + docId));
			}
		}
		catch (Exception e) {
			logger.error(new FedExLogEntry("Error processing App Role Stanza for DocId " + docId), e);
			appRoleData = null;
		}
		return appRoleData;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\cds\CdsSecurityAppRole.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */