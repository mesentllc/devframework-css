package com.fedex.cds;

import com.fedex.common.icefaces.util.FacesUtils;
import com.fedex.ea.framework.securityapi.dao.esc.EscDaoException;
import com.fedex.enterprise.security.cds.authZ.Role;
import com.fedex.enterprise.security.esc.view.model.WssoHandler;
import com.fedex.enterprise.security.role.restriction.Entry;
import com.fedex.enterprise.security.role.restriction.RestrictionData;
import com.fedex.enterprise.security.role.restriction.RestrictionDataItem;
import com.fedex.enterprise.security.role.restriction.RestrictionSequence;
import com.fedex.enterprise.security.utils.EscUtils;
import com.fedex.enterprise.security.utils.SecurityDataBaseClass;
import com.fedex.framework.cds.CompositeResponse;
import com.fedex.framework.cds.IndexElementType;
import com.fedex.framework.cds.IndexQueryResponse;
import com.fedex.framework.cds.InsertRequest;
import com.fedex.framework.cds.KeyQueryRequest;
import com.fedex.framework.cds.KeyQueryResponse;
import com.fedex.framework.cds.KeyedStanzasType;
import com.fedex.framework.cds.SequenceResponse;
import com.fedex.framework.cds.StanzaIdType;
import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import com.fedex.xmlns.cds.authz.Restriction;
import org.springframework.ws.soap.client.SoapFaultClientException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.faces.context.FacesContext;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.ws.soap.SOAPFaultException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class CdsSecurityRestriction
		extends CdsSecurityBase {
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(CdsSecurityRole.class);
	private static JAXBContext cdsRestrictionContext = null;
	private static Unmarshaller cdsRestrictionUnmarshaller = null;

	static {
		try {
			cdsRestrictionContext = JAXBContext.newInstance("com.fedex.xmlns.cds.authz");
			cdsRestrictionUnmarshaller = cdsRestrictionContext.createUnmarshaller();
		}
		catch (JAXBException e) {
			logger.error(new FedExLogEntry("Error initializing CDS Restriction Unmarshaller : " + e.getMessage()), e);
			throw new RuntimeException("Error initializing CDS Restriction Unmarshaller : " + e.getMessage(), e);
		}
	}

	private static List<IndexElementType> BuildIndexQuery(String appID, String roleName, String userId) {
		List<IndexElementType> indexElements = new ArrayList();
		IndexElementType appId = new IndexElementType();
		appId.setXpath("/restriction/APPID");
		appId.setComparison("equals");
		appId.setValue(appID);
		indexElements.add(appId);
		if (!EscUtils.isNullOrBlank(roleName)) {
			IndexElementType byRoleName = new IndexElementType();
			byRoleName.setXpath("/restriction/ROLENAME");
			byRoleName.setComparison("equals");
			byRoleName.setValue(roleName);
			indexElements.add(byRoleName);
		}
		if (!EscUtils.isNullOrBlank(userId)) {
			IndexElementType byUserId = new IndexElementType();
			byUserId.setXpath("/restriction/USERID");
			byUserId.setComparison("equals");
			byUserId.setValue(userId);
			indexElements.add(byUserId);
		}
		return indexElements;
	}

	public static List<RestrictionData> RetrieveRoleRestrictions(Bookmark bookmarkId, String appId) {
		String bookmark = "";
		List<RestrictionData> response = new ArrayList();
		int totalDocCount = 0;
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		if (bookmarkId == null) {
			bookmarkId = new Bookmark();
			bookmarkId.setBookmark("5120135");
		}
		StanzaIdType stanzaId = of.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("restriction");
		StanzaIdType indexStanzaId = of.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("restriction");
		Unmarshaller unmarshaller;
		do {
			IndexQueryResponse indexResponse = cdsClient.indexQuery(BuildIndexQuery(appId, null, null), stanzaId, indexStanzaId, bookmark);
			List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
			JAXBContext context = null;
			unmarshaller = null;
			try {
				context = JAXBContext.newInstance(Restriction.class);
				unmarshaller = context.createUnmarshaller();
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRestriction RetrieveRoleRestrictions new instance or create unmarshaller"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
				for (Iterator i$ = queryItem.getKeyedStanzas().iterator(); i$.hasNext(); ) {
					KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
					totalDocCount++;
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						Restriction currentRestriction = null;
						try {
							currentRestriction = (Restriction)unmarshaller.unmarshal(docElement);
							RestrictionData restrictionData = new RestrictionData();
							restrictionData.setRoleDocId(currentRestriction.getROLEDOCID());
							restrictionData.setDocId(keyedStanzas.getKey());
							restrictionData.setRoleNm(currentRestriction.getROLENAME());
							if (currentRestriction.getUSERID().getEmployeeId() != null) {
								restrictionData.setEmplId(currentRestriction.getUSERID().getEmployeeId());
							}
							if (currentRestriction.getUSERID().getGroupName() != null) {
								restrictionData.setGroupNm(currentRestriction.getUSERID().getGroupName());
							}
							restrictionData.setAppId(Long.toString(currentRestriction.getAPPID()));
							List<RestrictionDataItem> resItemList = new ArrayList();
							for (Restriction.RestrictionItem referenceData : currentRestriction.getRestrictionItem()) {
								RestrictionDataItem resDataItem = new RestrictionDataItem();
								List<Entry> itemList = new ArrayList();
								for (Restriction.RestrictionItem.Entry entry : referenceData.getEntry()) {
									Entry newEntry = new Entry();
									newEntry.setKey(entry.getKey());
									newEntry.setValue(entry.getValue());
									itemList.add(newEntry);
								}
								resDataItem.setRestrictionItemIndex(referenceData.getRestrictionDataItemIndex());
								resDataItem.setEntryList(itemList);
								resItemList.add(resDataItem);
							}
							restrictionData.setRestrictionList(resItemList);
							response.add(restrictionData);
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRestriction RetrieveRoleRestrictions unmarshal"), e);
						}
						continue;
					}
				}
				bookmark = queryItem.getPaging().getBookmark();
			}
		}
		while ((!"".equals(bookmark)) && (bookmarkId.getBookmark() == "5120135"));
		bookmarkId.setBookmark(bookmark);
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR APPLICATION RESTRICTIONS = " + totalDocCount + " for App Id: " + appId));
		return response;
	}

	public static long InsertRestriction(RestrictionData newObject) {
		return InsertRestriction(newObject, false);
	}

	public static long InsertRestriction(RestrictionData newObject, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		if (!systemOverride) {
			WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
			onBehalfOf = roleHandler.getUserId();
		}
		return InsertRestriction(newObject, systemOverride, onBehalfOf, "");
	}

	public static long InsertRestriction(RestrictionData newObject, boolean systemOverride, String onBehalfOf, String appId) {
		List<Document> request = new ArrayList();
		try {
			com.fedex.xmlns.cds.authz.ObjectFactory securityObjectFactory = new com.fedex.xmlns.cds.authz.ObjectFactory();
			JAXBContext propJaxbContext = JAXBContext.newInstance("com.fedex.xmlns.cds.authz");
			Marshaller propMarshaller = propJaxbContext.createMarshaller();
			Restriction cdsRestriction = securityObjectFactory.createRestriction();
			cdsRestriction.setAPPID(Long.parseLong(newObject.getAppId()));
			cdsRestriction.setROLEDOCID(newObject.getRoleDocId());
			cdsRestriction.setROLENAME(newObject.getRoleNm());
			cdsRestriction.setUSERID(new Restriction.USERID());
			if ((newObject.getEmplId() != null) && (!newObject.getEmplId().equalsIgnoreCase(""))) {
				cdsRestriction.getUSERID().setEmployeeId(newObject.getEmplId());
			}
			if ((newObject.getGroupNm() != null) && (!newObject.getGroupNm().equalsIgnoreCase(""))) {
				cdsRestriction.getUSERID().setGroupName(newObject.getGroupNm());
			}
			List<Restriction.RestrictionItem> restrictionItemList = new ArrayList();
			for (RestrictionDataItem item : newObject.getRestrictionList()) {
				Restriction.RestrictionItem resItem = new Restriction.RestrictionItem();
				resItem.setRestrictionDataItemIndex(item.getRestrictionItemIndex());
				List<Restriction.RestrictionItem.Entry> entryList = new ArrayList();
				for (Entry entry : item.getEntry()) {
					Restriction.RestrictionItem.Entry newEntry = new Restriction.RestrictionItem.Entry();
					newEntry.setKey(entry.getKey());
					newEntry.setValue(entry.getValue());
					entryList.add(newEntry);
				}
				resItem.getEntry().addAll(entryList);
				restrictionItemList.add(resItem);
			}
			cdsRestriction.getRestrictionItem().addAll(restrictionItemList);
			cdsRestriction.setDomain("authZ");
			cdsRestriction.setMajorVersion(STANZA_DESC_MAJOR_VER);
			cdsRestriction.setMinorVersion(STANZA_DESC_MINOR_VER);
			Document doc = BuildDocument();
			propMarshaller.marshal(cdsRestriction, doc);
			request.add(doc);
			String callingApp = "";
			if (EscUtils.isNullOrBlank(appId)) {
				if (newObject.getAppId().isEmpty()) {
					callingApp = "4112";
				}
				else {
					callingApp = EscUtils.formatStaticAppId(newObject.getAppId());
				}
			}
			else {
				callingApp = appId;
			}
			InsertRequest.InsertItem auditRecord = createStaticAuditRecord(callingApp, onBehalfOf, "restriction", "create", "role");
			List<InsertRequest.InsertItem> auditRecords = new ArrayList();
			auditRecords.add(auditRecord);
			List<Long> keys = cdsClient.insert(request, auditRecords, systemOverride);
			newObject.setDocId(keys.get(0).longValue());
		}
		catch (SoapFaultClientException sfx) {
			throw sfx;
		}
		catch (JAXBException jbEx) {
			logger.error(new FedExLogEntry("Caught General JAXBException in CdsSecurityRestriction InsertRestriction "), jbEx);
			logger.warn(new FedExLogEntry("Caught JAXB Exception ex: " + jbEx.toString()));
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Caught general Exception ex: " + e.toString()));
			logger.error(new FedExLogEntry("Caught General Exception in CdsSecurityRestriction InsertRestriction "), e);
		}
		return newObject.getDocId();
	}

	public static List<RestrictionData> RetrieveRestrictionsByRoleNameEmpId(String appId, String roleName, String userId) {
		List<RestrictionData> restrictionList = new ArrayList();
		String bookmark = "";
		int totalDocCount = 0;
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		StanzaIdType stanzaId = of.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("restriction");
		StanzaIdType indexStanzaId = of.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("restriction");
		IndexQueryResponse indexResponse = cdsClient.indexQuery(BuildIndexQuery(appId, roleName, userId), stanzaId, indexStanzaId, "");
		List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
		JAXBContext context = null;
		Unmarshaller unmarshaller = null;
		try {
			context = JAXBContext.newInstance(Restriction.class);
			unmarshaller = context.createUnmarshaller();
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRestriction RetrieveRestrictionsByRoleNameEmpId create unmarshaller "), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
			for (Iterator i$ = queryItem.getKeyedStanzas().iterator(); i$.hasNext(); ) {
				KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
				totalDocCount++;
				List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
				for (KeyedStanzasType.Stanza s : stanzaList) {
					Element docElement = s.getAny();
					Restriction currentRestriction = null;
					try {
						currentRestriction = (Restriction)unmarshaller.unmarshal(docElement);
						RestrictionData restrictionData = new RestrictionData();
						restrictionData.setRoleDocId(currentRestriction.getROLEDOCID());
						restrictionData.setDocId(keyedStanzas.getKey());
						restrictionData.setRoleNm(currentRestriction.getROLENAME());
						restrictionData.setEmplId(currentRestriction.getUSERID().getEmployeeId());
						restrictionData.setGroupNm(currentRestriction.getUSERID().getGroupName());
						restrictionData.setAppId(Long.toString(currentRestriction.getAPPID()));
						List<RestrictionDataItem> resItemList = new ArrayList();
						for (Restriction.RestrictionItem referenceData : currentRestriction.getRestrictionItem()) {
							List<Entry> itemList = new ArrayList();
							for (Restriction.RestrictionItem.Entry entry : referenceData.getEntry()) {
								String key = entry.getKey();
								String value = entry.getValue();
								Entry newEntry = new Entry();
								newEntry.setKey(key);
								newEntry.setValue(value);
								itemList.add(newEntry);
							}
							RestrictionDataItem resDataItem = new RestrictionDataItem();
							resDataItem.setRestrictionItemIndex(referenceData.getRestrictionDataItemIndex());
							resDataItem.setEntryList(itemList);
							resItemList.add(resDataItem);
						}
						restrictionData.setRestrictionList(resItemList);
						restrictionData.toString();
						restrictionList.add(restrictionData);
					}
					catch (JAXBException e) {
						logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRestriction RetrieveRestrictionsByRoleNameEmpId "), e);
					}
					continue;
				}
			}
		}
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR APPLICATION RESTRICTIONS = " + totalDocCount + " for App Id: " + appId));
		return restrictionList;
	}

	public static List<RestrictionData> RetrieveRestrictionsByRoleName(String appId, String roleName, Bookmark bookmarkId) {
		List<RestrictionData> restrictionList = new ArrayList();
		String bookmark = "";
		int totalDocCount = 0;
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		if (bookmarkId == null) {
			bookmarkId = new Bookmark();
			bookmarkId.setBookmark("5120135");
		}
		StanzaIdType stanzaId = of.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("restriction");
		StanzaIdType indexStanzaId = of.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("restriction");
		Unmarshaller unmarshaller;
		do {
			IndexQueryResponse indexResponse = cdsClient.indexQuery(BuildIndexQuery(appId, roleName, null), stanzaId, indexStanzaId, bookmark);
			List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
			JAXBContext context = null;
			unmarshaller = null;
			try {
				context = JAXBContext.newInstance(Restriction.class);
				unmarshaller = context.createUnmarshaller();
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRestriction RetrieveRestrictionsByRoleName new instance or create unmarshaller "), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
				for (Iterator i$ = queryItem.getKeyedStanzas().iterator(); i$.hasNext(); ) {
					KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
					totalDocCount++;
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						Restriction currentRestriction = null;
						try {
							currentRestriction = (Restriction)unmarshaller.unmarshal(docElement);
							RestrictionData restrictionData = new RestrictionData();
							restrictionData.setRoleDocId(currentRestriction.getROLEDOCID());
							restrictionData.setDocId(keyedStanzas.getKey());
							restrictionData.setRoleNm(currentRestriction.getROLENAME());
							restrictionData.setEmplId(currentRestriction.getUSERID().getEmployeeId());
							restrictionData.setGroupNm(currentRestriction.getUSERID().getGroupName());
							restrictionData.setAppId(Long.toString(currentRestriction.getAPPID()));
							List<RestrictionDataItem> resItemList = new ArrayList();
							for (Restriction.RestrictionItem referenceData : currentRestriction.getRestrictionItem()) {
								List<Entry> itemList = new ArrayList();
								for (Restriction.RestrictionItem.Entry entry : referenceData.getEntry()) {
									String key = entry.getKey();
									String value = entry.getValue();
									Entry newEntry = new Entry();
									newEntry.setKey(key);
									newEntry.setValue(value);
									itemList.add(newEntry);
								}
								RestrictionDataItem resDataItem = new RestrictionDataItem();
								resDataItem.setRestrictionItemIndex(referenceData.getRestrictionDataItemIndex());
								resDataItem.setEntryList(itemList);
								resItemList.add(resDataItem);
							}
							restrictionData.setRestrictionList(resItemList);
							restrictionList.add(restrictionData);
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRestriction RetrieveRestrictionsByRoleName unmarshal "), e);
						}
						continue;
					}
				}
				bookmark = queryItem.getPaging().getBookmark();
			}
		}
		while ((!"".equals(bookmark)) && (bookmarkId.getBookmark() == "5120135"));
		bookmarkId.setBookmark(bookmark);
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR APPLICATION RESTRICTIONS = " + totalDocCount + " for App Id: " + appId));
		return restrictionList;
	}

	public static RestrictionData retrieveRestrictionByKey(long docId) {
		Unmarshaller unmarshaller = null;
		JAXBContext extRefStanzaContext = null;
		RestrictionData restrictionData = null;
		try {
			extRefStanzaContext = JAXBContext.newInstance(Role.class);
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRestriction RetrieveRestrictionsByRoleName new instance "), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		try {
			unmarshaller = extRefStanzaContext.createUnmarshaller();
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRestriction RetrieveRestrictionsByRoleName create unmarshaller "), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		try {
			List<Long> keys = new ArrayList();
			keys.add(Long.valueOf(docId));
			KeyQueryRequest request = buildKeyQueryRequest(keys, "restriction");
			KeyQueryResponse response = cdsClient.keyQuery(request);
			Iterator i$ = response.getKeyedStanzas().iterator();
			if (i$.hasNext()) {
				KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
				List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
				for (KeyedStanzasType.Stanza s : stanzaList) {
					Element docElement = s.getAny();
					Restriction currentRestriction = null;
					try {
						currentRestriction = (Restriction)unmarshaller.unmarshal(docElement);
						restrictionData = new RestrictionData();
						restrictionData.setRoleDocId(currentRestriction.getROLEDOCID());
						restrictionData.setDocId(keyedStanzas.getKey());
						restrictionData.setRoleNm(currentRestriction.getROLENAME());
						if (currentRestriction.getUSERID().getEmployeeId() != null) {
							restrictionData.setEmplId(currentRestriction.getUSERID().getEmployeeId());
						}
						if (currentRestriction.getUSERID().getGroupName() != null) {
							restrictionData.setGroupNm(currentRestriction.getUSERID().getGroupName());
						}
						restrictionData.setAppId(Long.toString(currentRestriction.getAPPID()));
						List<RestrictionDataItem> resItemList = new ArrayList();
						for (Restriction.RestrictionItem referenceData : currentRestriction.getRestrictionItem()) {
							RestrictionDataItem resDataItem = new RestrictionDataItem();
							List<Entry> itemList = new ArrayList();
							for (Restriction.RestrictionItem.Entry entry : referenceData.getEntry()) {
								Entry newEntry = new Entry();
								newEntry.setKey(entry.getKey());
								newEntry.setValue(entry.getValue());
								itemList.add(newEntry);
							}
							resDataItem.setEntryList(itemList);
							resItemList.add(resDataItem);
						}
						restrictionData.setRestrictionList(resItemList);
					}
					catch (JAXBException e) {
						logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRestriction RetrieveRestrictionsByRoleName unmarshal "), e);
					}
					continue;
				}
				return restrictionData;
			}
		}
		catch (SoapFaultClientException sfx) {
			throw sfx;
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Caught general Exception ex: " + e.toString()));
			throw new RuntimeException(e);
		}
		return restrictionData;
	}

	public static void DeleteRestriction(RestrictionData restriction) {
		DeleteRestriction(restriction, false);
	}

	public static void DeleteRestriction(RestrictionData restriction, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		try {
			if ((!systemOverride) && (FacesContext.getCurrentInstance() != null)) {
				WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
				onBehalfOf = roleHandler.getUserId();
			}
		}
		catch (SOAPFaultException sfe) {
			throw new RuntimeException(sfe.getMessage(), sfe);
		}
		DeleteRestriction(restriction, systemOverride, onBehalfOf, "");
	}

	public static void DeleteRestriction(RestrictionData restricton, boolean systemOverride, String onBehalfOf, String appId) {
		String callingApp = "";
		try {
			if (EscUtils.isNullOrBlank(appId)) {
				if (restricton.getAppId().isEmpty()) {
					callingApp = "4112";
				}
				else {
					callingApp = EscUtils.formatStaticAppId(restricton.getAppId());
				}
			}
			else {
				callingApp = appId;
			}
			String desc = "Restriction for app " + restricton.getAppId() + ", role " + restricton.getRoleNm() + ", user/group " + (restricton.getEmplId() != null ? restricton.getEmplId() : restricton.getGroupNm()) + " was deleted by " + onBehalfOf + " from " + (callingApp.equals("4112") ? "the ESC." : new StringBuilder().append("App #").append(callingApp).toString());
			InsertRequest.InsertItem auditRecord = createStaticAuditRecord(callingApp, onBehalfOf, desc, "delete", "restriction");
			Delete(Long.valueOf(restricton.getDocId()), "restriction", auditRecord, systemOverride);
		}
		catch (SecurityException se) {
			throw new RuntimeException(se.getMessage(), se);
		}
	}

	public static CompositeResponse UpdateRestriction(RestrictionData restriction) {
		return UpdateRestriction(restriction, false);
	}

	public static CompositeResponse UpdateRestriction(RestrictionData restriction, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		if (!systemOverride) {
			WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
			onBehalfOf = roleHandler.getUserId();
		}
		return UpdateRestriction(restriction, systemOverride, onBehalfOf, "");
	}

	public static CompositeResponse UpdateRestriction(RestrictionData restrictionData, boolean systemOverride, String onBehalfOf, String appId) {
		CompositeResponse response = null;
		String callingApp = "";
		if (EscUtils.isNullOrBlank(appId)) {
			if (restrictionData.getAppId().isEmpty()) {
				callingApp = "4112";
			}
			else {
				callingApp = EscUtils.formatStaticAppId(restrictionData.getAppId());
			}
		}
		else {
			callingApp = appId;
		}
		String desc = "Restriction for employee: 827904associated with role: " + restrictionData.getRoleNm() + " was modified by " + onBehalfOf + " from " + (callingApp.equals("4112") ? "the ESC." : new StringBuilder().append("App #").append(callingApp).toString());
		InsertRequest.InsertItem auditRecord = createStaticAuditRecord(callingApp, onBehalfOf, desc, "modify", "restriction");
		com.fedex.xmlns.cds.authz.ObjectFactory restrictionObjectFactory = null;
		Marshaller propMarshaller = null;
		try {
			restrictionObjectFactory = new com.fedex.xmlns.cds.authz.ObjectFactory();
			JAXBContext propJaxbContext = JAXBContext.newInstance("com.fedex.xmlns.cds.authz");
			propMarshaller = propJaxbContext.createMarshaller();
		}
		catch (Exception e) {
			logger.error(new FedExLogEntry("Exception caught"));
		}
		Restriction cdsRestriction = restrictionObjectFactory.createRestriction();
		cdsRestriction.setAPPID(Long.parseLong(restrictionData.getAppId()));
		cdsRestriction.setROLEDOCID(restrictionData.getRoleDocId());
		cdsRestriction.setROLENAME(restrictionData.getRoleNm());
		cdsRestriction.setUSERID(new Restriction.USERID());
		if (!EscUtils.isNullOrBlank(restrictionData.getEmplId())) {
			cdsRestriction.getUSERID().setEmployeeId(restrictionData.getEmplId());
		}
		else {
			cdsRestriction.getUSERID().setGroupName(restrictionData.getGroupNm());
		}
		List<Restriction.RestrictionItem> restrictionItemList = new ArrayList();
		for (RestrictionDataItem item : restrictionData.getRestrictionList()) {
			Restriction.RestrictionItem resItem = new Restriction.RestrictionItem();
			resItem.setRestrictionDataItemIndex(item.getRestrictionItemIndex());
			List<Restriction.RestrictionItem.Entry> entryList = new ArrayList();
			for (Entry entry : item.getEntry()) {
				Restriction.RestrictionItem.Entry newEntry = new Restriction.RestrictionItem.Entry();
				newEntry.setKey(entry.getKey());
				newEntry.setValue(entry.getValue());
				entryList.add(newEntry);
			}
			resItem.getEntry().addAll(entryList);
			restrictionItemList.add(resItem);
		}
		cdsRestriction.getRestrictionItem().addAll(restrictionItemList);
		cdsRestriction.setDomain("authZ");
		cdsRestriction.setMajorVersion(STANZA_DESC_MAJOR_VER);
		cdsRestriction.setMinorVersion(STANZA_DESC_MINOR_VER);
		Document doc = BuildDocument();
		try {
			propMarshaller.marshal(cdsRestriction, doc);
		}
		catch (JAXBException e) {
			logger.error(new FedExLogEntry("JAXBException was caught while marshalling restriction document: " + e.getMessage()), e);
		}
		Element restrictionElement = doc.getDocumentElement();
		try {
			response = cdsClient.update("/restriction", restrictionData.getDocId(), "authZ", "restriction", auditRecord, false, restrictionElement);
		}
		catch (Exception e) {
			logger.error(new FedExLogEntry("Exception was caught while modifying a restriction" + e.getMessage()), e);
		}
		return response;
	}

	public static String requestSingleSequence() {
		SequenceResponse response = cdsClient.restrictionSequenceRequest(1);
		String sequence = "";
		if ((!EscUtils.isNullOrBlank(response.getEndSequence())) && (!EscUtils.isNullOrBlank(response.getStartSequence())) && (response.getStartSequence().equalsIgnoreCase(response.getEndSequence()))) {
			sequence = response.getEndSequence();
		}
		return sequence;
	}

	public static RestrictionSequence requestMultipleSequences(int amount) {
		RestrictionSequence resSequence = new RestrictionSequence();
		SequenceResponse response = cdsClient.restrictionSequenceRequest(amount);
		if ((!EscUtils.isNullOrBlank(response.getEndSequence())) && (!EscUtils.isNullOrBlank(response.getStartSequence()))) {
			resSequence.setStartIndex(response.getStartSequence());
			resSequence.setEndIndex(response.getEndSequence());
		}
		return resSequence;
	}

	private static List<RestrictionData> castList(List<SecurityDataBaseClass> tempList) {
		List<RestrictionData> list = new ArrayList(tempList.size());
		for (SecurityDataBaseClass base : tempList) {
			list.add((RestrictionData)base);
		}
		return list;
	}

	public static List<RestrictionData> getRoleDataRestrictionInfo(String roleName, String appId)
			throws EscDaoException {
		List<SecurityDataBaseClass> dataList = cdsClient.indexQuery("/restriction/APPID", CdsClient.QUERY_COMPARE.equals, appId, "/restriction/ROLENAME", CdsClient.QUERY_COMPARE.equals, roleName, "authZ", CdsSecurityBase.STANZAS.restriction, "authZ", CdsSecurityBase.STANZAS.restriction, true);
		return castList(dataList);
	}

	public static RestrictionData processRestrictionRoleStanza(long docId, KeyedStanzasType.Stanza restrictionStanza) {
		Restriction restriction = null;
		RestrictionData restrictionData = null;
		try {
			Element docElement = restrictionStanza.getAny();
			restriction = (Restriction)cdsRestrictionUnmarshaller.unmarshal(docElement);
			if (restriction != null) {
				restrictionData = new RestrictionData();
				restrictionData.setRoleDocId(restriction.getROLEDOCID());
				restrictionData.setDocId(docId);
				restrictionData.setRoleNm(restriction.getROLENAME());
				restrictionData.setEmplId(restriction.getUSERID().getEmployeeId());
				restrictionData.setGroupNm(restriction.getUSERID().getGroupName());
				restrictionData.setAppId(Long.toString(restriction.getAPPID()));
				List<RestrictionDataItem> resItemList = new ArrayList();
				for (Restriction.RestrictionItem referenceData : restriction.getRestrictionItem()) {
					List<Entry> itemList = new ArrayList();
					for (Restriction.RestrictionItem.Entry entry : referenceData.getEntry()) {
						String key = entry.getKey();
						String value = entry.getValue();
						Entry newEntry = new Entry();
						newEntry.setKey(key);
						newEntry.setValue(value);
						itemList.add(newEntry);
					}
					RestrictionDataItem resDataItem = new RestrictionDataItem();
					resDataItem.setEntryList(itemList);
					resItemList.add(resDataItem);
				}
				restrictionData.setRestrictionList(resItemList);
			}
			else {
				logger.info(new FedExLogEntry("App Role is null after unmarshalling Stanza for DocId " + docId));
			}
		}
		catch (Exception e) {
			logger.error(new FedExLogEntry("Error processing App Role Stanza for DocId " + docId), e);
			restrictionData = null;
		}
		return restrictionData;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\cds\CdsSecurityRestriction.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */