package com.fedex.cds;

import com.fedex.common.icefaces.util.FacesUtils;
import com.fedex.ea.framework.securityapi.dao.esc.EscDaoException;
import com.fedex.enterprise.security.cds.authZ.UserRole;
import com.fedex.enterprise.security.esc.view.model.WssoHandler;
import com.fedex.enterprise.security.role.RoleData;
import com.fedex.enterprise.security.role.UserRoleData;
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
import org.springframework.ws.soap.client.SoapFaultClientException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.faces.context.FacesContext;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class CdsSecurityUserRole
		extends CdsSecurityBase {
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(CdsSecurityUserRole.class);

	public static long Insert(UserRoleData userRoleData, long roleDocId) {
		return Insert(userRoleData, roleDocId, false);
	}

	public static long Insert(UserRoleData userRoleData, long roleDocId, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		if ((!systemOverride) && (FacesContext.getCurrentInstance() != null)) {
			WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
			onBehalfOf = roleHandler.getUserId();
		}
		return Insert(userRoleData, roleDocId, systemOverride, onBehalfOf, "");
	}

	public static long Insert(UserRoleData userRoleData, long roleDocId, boolean systemOverride, String onBehalfOf, String appId) {
		logger.info(new FedExLogEntry("Insert UserRoleData: " + userRoleData + " with roleDocId = " + roleDocId));
		List<Document> request = new ArrayList();
		try {
			RoleData role = CdsSecurityRole.Retrieve(roleDocId, false);
			com.fedex.enterprise.security.cds.authZ.ObjectFactory securityObjectFactory = new com.fedex.enterprise.security.cds.authZ.ObjectFactory();
			JAXBContext propJaxbContext = JAXBContext.newInstance("com.fedex.enterprise.security.cds.authZ");
			Marshaller propMarshaller = propJaxbContext.createMarshaller();
			UserRole cdsUserRole = securityObjectFactory.createUserRole();
			if (roleDocId != 0L) {
				cdsUserRole.setRoleDocId(roleDocId);
			}
			else {
				cdsUserRole.setRoleDocId(userRoleData.getRoleDocId());
			}
			cdsUserRole.setUserFedExId(userRoleData.getEmpNbr());
			if (!EscUtils.isNullOrBlank(onBehalfOf)) {
				cdsUserRole.setAssignedBy(onBehalfOf);
			}
			cdsUserRole.setDateAssigned(getStaticDateTime());
			cdsUserRole.setDomain("authZ");
			cdsUserRole.setMajorVersion(STANZA_DESC_MAJOR_VER);
			cdsUserRole.setMinorVersion(STANZA_DESC_MINOR_VER);
			Document doc = BuildDocument();
			propMarshaller.marshal(cdsUserRole, doc);
			request.add(doc);
			String callingApp = "";
			if (EscUtils.isNullOrBlank(appId)) {
				callingApp = "4112";
			}
			else {
				callingApp = appId;
			}
			String desc = userRoleData.getEmpNbr() + " was added to the " + role.getRoleNm() + " role by " + onBehalfOf + " from " + (callingApp.equals("4112") ? "the ESC." : new StringBuilder().append("App #").append(callingApp).toString());
			InsertRequest.InsertItem auditRecord = createStaticAuditRecord(role.getRoleScopeNm(), onBehalfOf, desc, "create", "userRole");
			List<InsertRequest.InsertItem> auditRecords = new ArrayList();
			auditRecords.add(auditRecord);
			List<Long> keys = cdsClient.insert(request, auditRecords, systemOverride);
			userRoleData.setDocId(keys.get(0).longValue());
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
		return userRoleData.getDocId();
	}

	public static UserRoleData RetrieveByKey(long docId) {
		Unmarshaller unmarshaller = null;
		JAXBContext extRefStanzaContext = null;
		UserRoleData userRoleData = null;
		try {
			extRefStanzaContext = JAXBContext.newInstance(UserRole.class);
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityUserRole RetrieveByKey UserRoleData new instance "), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		try {
			unmarshaller = extRefStanzaContext.createUnmarshaller();
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityUserRole RetrieveByKey UserRoleData create unmarshaller "), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		try {
			List<Long> keys = new ArrayList();
			keys.add(Long.valueOf(docId));
			KeyQueryRequest request = buildKeyQueryRequest(keys, "userRole");
			KeyQueryResponse response = cdsClient.keyQuery(request);
			for (Iterator i$ = response.getKeyedStanzas().iterator(); i$.hasNext(); ) {
				KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
				List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
				for (KeyedStanzasType.Stanza s : stanzaList) {
					Element docElement = s.getAny();
					UserRole currentUserRole = null;
					try {
						currentUserRole = (UserRole)unmarshaller.unmarshal(docElement);
						userRoleData = new UserRoleData();
						userRoleData.setEmpNbr(currentUserRole.getUserFedExId());
						userRoleData.setRoleDocId(currentUserRole.getRoleDocId());
						userRoleData.setDocId(keyedStanzas.getKey());
						if (!EscUtils.isNullOrBlank(currentUserRole.getAssignedBy())) {
							userRoleData.setAssignedBy(currentUserRole.getAssignedBy());
						}
						if (currentUserRole.getDateAssigned() != null) {
							userRoleData.setDateAssigned(currentUserRole.getDateAssigned().toGregorianCalendar());
						}
					}
					catch (JAXBException e) {
						logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityUserRole RetrieveByKey UserRoleData unmarshal "), e);
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
		return userRoleData;
	}

	public static List<UserRoleData> retrieveForRuleAppId(String ruleAppId, boolean mapObjects) throws EscDaoException {
		List<SecurityDataBaseClass> baseList = cdsClient.indexQuery("/rule/@ApplicationId", CdsClient.QUERY_COMPARE.equals, ruleAppId, "authZ", CdsSecurityBase.STANZAS.rule, "authZ", CdsSecurityBase.STANZAS.userRole, mapObjects);
		return castList(baseList);
	}

	public static List<UserRoleData> Retrieve(long roleKey) {
		return Retrieve(roleKey, null, true);
	}

	public static List<UserRoleData> Retrieve(String userId) {
		return Retrieve(0L, userId, true);
	}

	public static List<UserRoleData> Retrieve(long roleKey, boolean ldapAttribs) {
		return Retrieve(roleKey, null, ldapAttribs);
	}

	public static List<UserRoleData> Retrieve(String userId, boolean ldapAttribs) {
		return Retrieve(0L, userId, ldapAttribs);
	}

	public static List<UserRoleData> Retrieve(long roleKey, String userId, boolean ldapAttribs) {
		String bookmark = "";
		List<UserRoleData> response = new ArrayList();
		int totalDocCount = 0;
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		StanzaIdType stanzaId = of.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("userRole");
		StanzaIdType indexStanzaId = of.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("userRole");
		IndexQueryResponse indexResponse = null;
		Unmarshaller unmarshaller;
		do {
			try {
				indexResponse = cdsClient.indexQuery(BuildIndexQuery(roleKey, userId), stanzaId, indexStanzaId, bookmark);
			}
			catch (SoapFaultClientException sfx) {
				throw sfx;
			}
			List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
			JAXBContext resourceStanzaContext = null;
			unmarshaller = null;
			try {
				resourceStanzaContext = JAXBContext.newInstance(UserRole.class);
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityUserRole Retrieve UserRoleData ArrayList new instance "), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			try {
				unmarshaller = resourceStanzaContext.createUnmarshaller();
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityUserRole Retrieve UserRoleData ArrayList create unmarshaller "), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
				for (Iterator i$ = queryItem.getKeyedStanzas().iterator(); i$.hasNext(); ) {
					KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
					totalDocCount++;
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						UserRole currentUserRole = null;
						try {
							currentUserRole = (UserRole)unmarshaller.unmarshal(docElement);
							UserRoleData newUserRoleData = new UserRoleData();
							newUserRoleData.setDocId(keyedStanzas.getKey());
							newUserRoleData.setEmpNbr(currentUserRole.getUserFedExId());
							newUserRoleData.setRoleDocId(currentUserRole.getRoleDocId());
							if (!EscUtils.isNullOrBlank(currentUserRole.getAssignedBy())) {
								newUserRoleData.setAssignedBy(currentUserRole.getAssignedBy());
							}
							if (currentUserRole.getDateAssigned() != null) {
								newUserRoleData.setDateAssigned(currentUserRole.getDateAssigned().toGregorianCalendar());
							}
							if (ldapAttribs) {
								LDAPUserRecord record = ldapSearch.getUserAttribs(newUserRoleData.getEmpNbr());
								logger.info(new FedExLogEntry("Record returned from LDAP: " + record));
								if ((record.getNickName() != null) && (!"".equals(record.getNickName().trim()))) {
									newUserRoleData.setFirstName(record.getNickName());
								}
								else {
									newUserRoleData.setFirstName(record.getFirstName());
								}
								newUserRoleData.setLastName(record.getLastName());
							}
							response.add(newUserRoleData);
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityUserRole Retrieve UserRoleData ArrayList unmarshal "), e);
						}
						continue;
					}
				}
				bookmark = queryItem.getPaging().getBookmark();
			}
		}
		while (!"".equals(bookmark));
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR USER MEMBERS = " + totalDocCount));
		return response;
	}

	public static List<Long> RetrieveRoleDocIds(String userId) {
		String bookmark = "";
		List<Long> roleDocIds = new ArrayList();
		int totalDocCount = 0;
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		StanzaIdType stanzaId = of.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("userRole");
		StanzaIdType indexStanzaId = of.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("userRole");
		IndexQueryResponse indexResponse = null;
		do {
			try {
				indexResponse = cdsClient.indexQuery(BuildIndexQuery(0L, userId), stanzaId, indexStanzaId, bookmark);
			}
			catch (SoapFaultClientException sfx) {
				throw sfx;
			}
			Unmarshaller unmarshaller;
			Iterator i$;
			IndexQueryResponse.QueryItem queryItem;
			if (indexResponse != null) {
				List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
				JAXBContext resourceStanzaContext = null;
				unmarshaller = null;
				try {
					resourceStanzaContext = JAXBContext.newInstance(UserRole.class);
				}
				catch (JAXBException e1) {
					logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityUserRole RetrieveRoleDocIds new instance UserRole "), e1);
					throw new RuntimeException(e1.getMessage(), e1);
				}
				try {
					unmarshaller = resourceStanzaContext.createUnmarshaller();
				}
				catch (JAXBException e1) {
					logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityUserRole RetrieveRoleDocIds create unmarshaller "), e1);
					throw new RuntimeException(e1.getMessage(), e1);
				}
				for (i$ = queryItemList.iterator(); i$.hasNext(); ) {
					queryItem = (IndexQueryResponse.QueryItem)i$.next();
					for (KeyedStanzasType keyedStanzas : queryItem.getKeyedStanzas()) {
						totalDocCount++;
						List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
						for (KeyedStanzasType.Stanza s : stanzaList) {
							Element docElement = s.getAny();
							UserRole currentUserRole = null;
							try {
								currentUserRole = (UserRole)unmarshaller.unmarshal(docElement);
								roleDocIds.add(Long.valueOf(currentUserRole.getRoleDocId()));
							}
							catch (JAXBException e) {
								logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityUserRole RetrieveRoleDocIds unmarshal "), e);
							}
							continue;
						}
						bookmark = queryItem.getPaging().getBookmark();
					}
				}
			}
			else {
				logger.debug(new FedExLogEntry("The user id is not apart of any roles in ESC."));
			}
		}
		while (!"".equals(bookmark));
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR USER MEMBERS = " + totalDocCount));
		return roleDocIds;
	}

	private static List<IndexElementType> BuildIndexQuery(long roleDocID, String fedexId) {
		List<IndexElementType> indexElements = new ArrayList();
		if (roleDocID != 0L) {
			IndexElementType appId = new IndexElementType();
			appId.setXpath("/userRole/@RoleDocId");
			appId.setComparison("equals");
			appId.setValue(Long.toString(roleDocID));
			indexElements.add(appId);
		}
		if ((fedexId != null) && (!fedexId.isEmpty())) {
			IndexElementType userId = new IndexElementType();
			userId.setXpath("/userRole/@UserFedExId");
			userId.setComparison("equals");
			userId.setValue(fedexId);
			indexElements.add(userId);
		}
		return indexElements;
	}

	private static List<UserRoleData> castList(List<SecurityDataBaseClass> tempList) {
		List<UserRoleData> list = new ArrayList(tempList.size());
		for (SecurityDataBaseClass base : tempList) {
			list.add((UserRoleData)base);
		}
		return list;
	}

	public static List<UserRoleData> getRoleDataUserInfo(long roleKey)
			throws EscDaoException {
		List<SecurityDataBaseClass> dataList = cdsClient.indexQuery("/userRole/@RoleDocId", CdsClient.QUERY_COMPARE.equals, Long.toString(roleKey), "authZ", CdsSecurityBase.STANZAS.userRole, "authZ", CdsSecurityBase.STANZAS.userRole, true);
		return castList(dataList);
	}

	public static UserRoleData processUserRoleStanza(long docId, KeyedStanzasType.Stanza userStanza) {
		UserRole userRole = null;
		UserRoleData userRoleData = null;
		try {
			Element docElement = userStanza.getAny();
			userRole = (UserRole)cdsAuthZUnmarshaller.unmarshal(docElement);
			if (userRole != null) {
				userRoleData = new UserRoleData();
				userRoleData.setDocId(docId);
				userRoleData.setEmpNbr(userRole.getUserFedExId());
				userRoleData.setRoleDocId(userRole.getRoleDocId());
				userRoleData.setAssignedBy(userRole.getAssignedBy());
				userRoleData.setDateAssigned(userRole.getDateAssigned().toGregorianCalendar());
			}
			else {
				logger.info(new FedExLogEntry("User Role is null after unmarshalling Stanza for DocId " + docId));
			}
		}
		catch (Exception e) {
			logger.error(new FedExLogEntry("Error processing User Role Stanza for DocId " + docId), e);
			userRoleData = null;
		}
		return userRoleData;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\cds\CdsSecurityUserRole.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */