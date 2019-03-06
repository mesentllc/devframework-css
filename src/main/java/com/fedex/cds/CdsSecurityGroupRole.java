package com.fedex.cds;

import com.fedex.common.icefaces.util.FacesUtils;
import com.fedex.ea.framework.securityapi.dao.esc.EscDaoException;
import com.fedex.enterprise.security.cds.authZ.GroupRole;
import com.fedex.enterprise.security.esc.view.model.WssoHandler;
import com.fedex.enterprise.security.role.GroupRoleData;
import com.fedex.enterprise.security.role.RoleData;
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

import javax.faces.context.FacesContext;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class CdsSecurityGroupRole
		extends CdsSecurityBase {
	private static final String EQUALS = "equals";
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(CdsSecurityGroupRole.class);

	public static long Insert(GroupRoleData groupRoleData, long roleDocId) {
		return Insert(groupRoleData, roleDocId, false);
	}

	public static long Insert(GroupRoleData groupRoleData, long roleDocId, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		if ((!systemOverride) && (FacesContext.getCurrentInstance() != null)) {
			WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
			onBehalfOf = roleHandler.getUserId();
		}
		return Insert(groupRoleData, roleDocId, systemOverride, onBehalfOf, "");
	}

	public static long Insert(GroupRoleData groupRoleData, long roleDocId, boolean systemOverride, String onBehalfOf, String appId) {
		List<Document> request = new ArrayList();
		try {
			RoleData role = CdsSecurityRole.Retrieve(roleDocId, false);
			com.fedex.enterprise.security.cds.authZ.ObjectFactory securityObjectFactory = new com.fedex.enterprise.security.cds.authZ.ObjectFactory();
			JAXBContext propJaxbContext = JAXBContext.newInstance("com.fedex.enterprise.security.cds.authZ");
			Marshaller propMarshaller = propJaxbContext.createMarshaller();
			GroupRole cdsGroupRole = securityObjectFactory.createGroupRole();
			cdsGroupRole.setGroupName(groupRoleData.getGroupNm());
			if (roleDocId != 0L) {
				cdsGroupRole.setRoleDocId(roleDocId);
			}
			else {
				cdsGroupRole.setRoleDocId(groupRoleData.getRoleDocId());
			}
			if (!EscUtils.isNullOrBlank(onBehalfOf)) {
				cdsGroupRole.setAssignedBy(onBehalfOf);
			}
			cdsGroupRole.setDateAssigned(getStaticDateTime());
			cdsGroupRole.setDomain("authZ");
			cdsGroupRole.setMajorVersion(STANZA_DESC_MAJOR_VER);
			cdsGroupRole.setMinorVersion(STANZA_DESC_MINOR_VER);
			Document doc = BuildDocument();
			propMarshaller.marshal(cdsGroupRole, doc);
			request.add(doc);
			String callingApp = "";
			if (EscUtils.isNullOrBlank(appId)) {
				callingApp = "4112";
			}
			else {
				callingApp = appId;
			}
			String desc = groupRoleData.getGroupNm() + " was added to the " + role.getRoleNm() + " role by " + onBehalfOf + " from " + (callingApp.equals("4112") ? "the ESC." : new StringBuilder().append("App #").append(callingApp).toString());
			InsertRequest.InsertItem auditRecord = createStaticAuditRecord(role.getRoleScopeNm(), onBehalfOf, desc, "create", "groupRole");
			List<InsertRequest.InsertItem> auditRecords = new ArrayList();
			auditRecords.add(auditRecord);
			List<Long> keys = cdsClient.insert(request, auditRecords, systemOverride);
			groupRoleData.setDocId(keys.get(0).longValue());
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
		return groupRoleData.getDocId();
	}

	public static GroupRoleData RetrieveByKey(long docId) {
		Unmarshaller unmarshaller = null;
		JAXBContext extRefStanzaContext = null;
		GroupRoleData groupRoleData = null;
		try {
			extRefStanzaContext = JAXBContext.newInstance(GroupRole.class);
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityGroupRole RetrieveByKey new instance"), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		try {
			unmarshaller = extRefStanzaContext.createUnmarshaller();
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityGroupRole RetrieveByKey create unmarshaller"), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		try {
			List<Long> keys = new ArrayList();
			keys.add(Long.valueOf(docId));
			KeyQueryRequest request = buildKeyQueryRequest(keys, "groupRole");
			KeyQueryResponse response = cdsClient.keyQuery(request);
			for (Iterator i$ = response.getKeyedStanzas().iterator(); i$.hasNext(); ) {
				KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
				List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
				for (KeyedStanzasType.Stanza s : stanzaList) {
					Element docElement = s.getAny();
					GroupRole currentGroupRole = null;
					try {
						currentGroupRole = (GroupRole)unmarshaller.unmarshal(docElement);
						groupRoleData = new GroupRoleData();
						groupRoleData.setGroupNm(currentGroupRole.getGroupName());
						groupRoleData.setRoleDocId(currentGroupRole.getRoleDocId());
						if (!EscUtils.isNullOrBlank(currentGroupRole.getAssignedBy())) {
							groupRoleData.setAssignedBy(currentGroupRole.getAssignedBy());
						}
						if (currentGroupRole.getDateAssigned() != null) {
							groupRoleData.setDateAssigned(currentGroupRole.getDateAssigned().toGregorianCalendar());
						}
						groupRoleData.setDocId(keyedStanzas.getKey());
					}
					catch (JAXBException e) {
						logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityGroupRole RetrieveByKey unmarshal"), e);
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
		return groupRoleData;
	}

	public static List<GroupRoleData> retrieveForRuleAppId(String ruleAppId, boolean mapObjects) throws EscDaoException {
		List<SecurityDataBaseClass> baseList = cdsClient.indexQuery("/rule/@ApplicationId", CdsClient.QUERY_COMPARE.equals, ruleAppId, "authZ", CdsSecurityBase.STANZAS.rule, "authZ", CdsSecurityBase.STANZAS.groupRole, mapObjects);
		return castList(baseList);
	}

	public static List<GroupRoleData> Retrieve(long roleKey) {
		return Retrieve(roleKey, null);
	}

	public static List<GroupRoleData> Retrieve(String groupName) {
		return Retrieve(0L, groupName);
	}

	public static List<GroupRoleData> Retrieve(long roleKey, String groupName) {
		String bookmark = "";
		List<GroupRoleData> response = new ArrayList();
		int totalDocCount = 0;
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		StanzaIdType stanzaId = of.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("groupRole");
		StanzaIdType indexStanzaId = of.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("groupRole");
		IndexQueryResponse indexResponse = null;
		Unmarshaller unmarshaller;
		do {
			try {
				indexResponse = cdsClient.indexQuery(BuildIndexQuery(roleKey, groupName), stanzaId, indexStanzaId, bookmark);
			}
			catch (SoapFaultClientException sfx) {
				throw sfx;
			}
			List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
			JAXBContext resourceStanzaContext = null;
			unmarshaller = null;
			try {
				resourceStanzaContext = JAXBContext.newInstance(GroupRole.class);
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityGroupRole Retrieve new instance"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			try {
				unmarshaller = resourceStanzaContext.createUnmarshaller();
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityGroupRole Retrieve create unmarshaller"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
				for (Iterator i$ = queryItem.getKeyedStanzas().iterator(); i$.hasNext(); ) {
					KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
					totalDocCount++;
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						GroupRole currentGroupRole = null;
						try {
							currentGroupRole = (GroupRole)unmarshaller.unmarshal(docElement);
							GroupRoleData newGroupRoleData = new GroupRoleData();
							newGroupRoleData.setDocId(keyedStanzas.getKey());
							newGroupRoleData.setGroupNm(currentGroupRole.getGroupName());
							newGroupRoleData.setRoleDocId(currentGroupRole.getRoleDocId());
							if (!EscUtils.isNullOrBlank(currentGroupRole.getAssignedBy())) {
								newGroupRoleData.setAssignedBy(currentGroupRole.getAssignedBy());
							}
							if (currentGroupRole.getDateAssigned() != null) {
								newGroupRoleData.setDateAssigned(currentGroupRole.getDateAssigned().toGregorianCalendar());
							}
							response.add(newGroupRoleData);
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityGroupRole Retrieve unmarshal"), e);
						}
						continue;
					}
				}
				bookmark = queryItem.getPaging().getBookmark();
			}
		}
		while (!"".equals(bookmark));
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR GROUP MEMBERS = " + totalDocCount));
		return response;
	}

	public static List<GroupRoleData> RetrieveAllByRole(List<Long> roleKeys) {
		return RetrieveAll(roleKeys, null);
	}

	public static List<GroupRoleData> RetrieveAllByGroup(List<String> groupNames) {
		return RetrieveAll(null, groupNames);
	}

	public static List<GroupRoleData> RetrieveAll(List<Long> roleKeys, List<String> groupNames) {
		String bookmark = "";
		List<GroupRoleData> response = new ArrayList();
		int totalDocCount = 0;
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		StanzaIdType stanzaId = of.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("groupRole");
		StanzaIdType indexStanzaId = of.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("groupRole");
		IndexQueryResponse indexResponse = null;
		Unmarshaller unmarshaller;
		do {
			try {
				indexResponse = cdsClient.indexQuery(BuildBigIndexQuery(roleKeys, groupNames), stanzaId, indexStanzaId, bookmark);
			}
			catch (SoapFaultClientException sfx) {
				throw sfx;
			}
			List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
			JAXBContext resourceStanzaContext = null;
			unmarshaller = null;
			try {
				resourceStanzaContext = JAXBContext.newInstance(GroupRole.class);
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityGroupRole RetrieveAll new instance"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			try {
				unmarshaller = resourceStanzaContext.createUnmarshaller();
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityGroupRole RetrieveAll create unmarshall"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
				for (Iterator i$ = queryItem.getKeyedStanzas().iterator(); i$.hasNext(); ) {
					KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
					totalDocCount++;
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						GroupRole currentGroupRole = null;
						try {
							currentGroupRole = (GroupRole)unmarshaller.unmarshal(docElement);
							GroupRoleData newGroupRoleData = new GroupRoleData();
							newGroupRoleData.setDocId(keyedStanzas.getKey());
							newGroupRoleData.setGroupNm(currentGroupRole.getGroupName());
							newGroupRoleData.setRoleDocId(currentGroupRole.getRoleDocId());
							if (!EscUtils.isNullOrBlank(currentGroupRole.getAssignedBy())) {
								newGroupRoleData.setAssignedBy(currentGroupRole.getAssignedBy());
							}
							if (currentGroupRole.getDateAssigned() != null) {
								newGroupRoleData.setDateAssigned(currentGroupRole.getDateAssigned().toGregorianCalendar());
							}
							response.add(newGroupRoleData);
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityGroupRole RetrieveAll unmarshal"), e);
						}
						continue;
					}
				}
				bookmark = queryItem.getPaging().getBookmark();
			}
		}
		while (!"".equals(bookmark));
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR GROUP MEMBERS = " + totalDocCount));
		return response;
	}

	private static List<IndexElementType> BuildIndexQuery(long roleDocID, String groupName) {
		List<IndexElementType> indexElements = new ArrayList();
		if (roleDocID != 0L) {
			IndexElementType appId = new IndexElementType();
			appId.setXpath("/groupRole/@RoleDocId");
			appId.setComparison("equals");
			appId.setValue(Long.toString(roleDocID));
			indexElements.add(appId);
		}
		if ((groupName != null) && (!groupName.isEmpty())) {
			IndexElementType appId = new IndexElementType();
			appId.setXpath("/groupRole/@GroupName");
			appId.setComparison("equals");
			appId.setValue(groupName);
			indexElements.add(appId);
		}
		return indexElements;
	}

	private static List<IndexElementType> BuildBigIndexQuery(List<Long> roleDocIDs, List<String> groupNames) {
		List<IndexElementType> indexElements = new ArrayList();
		if (roleDocIDs != null) {
			for (Long roleDocID : roleDocIDs) {
				IndexElementType appId = new IndexElementType();
				appId.setXpath("/groupRole/@RoleDocId");
				appId.setComparison("equals");
				appId.setValue(Long.toString(roleDocID.longValue()));
				indexElements.add(appId);
			}
		}
		if (groupNames != null) {
			for (String groupName : groupNames) {
				IndexElementType appId = new IndexElementType();
				appId.setXpath("/groupRole/@GroupName");
				appId.setComparison("equals");
				appId.setValue(groupName);
				indexElements.add(appId);
			}
		}
		if (indexElements.size() > 500) {
			logger.error(new FedExLogEntry("WE JUST EXCEEDED THE 500 ELEMENT LIMIT FOR THE INDEX QUERY."));
		}
		return indexElements;
	}

	public static List<Long> RetrieveGroupRoleDocIds(String groupId) {
		String bookmark = "";
		List<Long> roleDocIds = new ArrayList();
		int totalDocCount = 0;
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		StanzaIdType stanzaId = of.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("groupRole");
		StanzaIdType indexStanzaId = of.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("groupRole");
		IndexQueryResponse indexResponse = null;
		Unmarshaller unmarshaller;
		Iterator i$;
		IndexQueryResponse.QueryItem queryItem;
		do {
			try {
				indexResponse = cdsClient.indexQuery(BuildIndexQuery(0L, groupId), stanzaId, indexStanzaId, bookmark);
			}
			catch (SoapFaultClientException sfx) {
				throw sfx;
			}
			List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
			JAXBContext resourceStanzaContext = null;
			unmarshaller = null;
			try {
				resourceStanzaContext = JAXBContext.newInstance(GroupRole.class);
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityGroupRole RetrieveGroupRoleDocIds new instance"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			try {
				unmarshaller = resourceStanzaContext.createUnmarshaller();
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityGroupRole RetrieveGroupRoleDocIds create unmarshaller"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			for (i$ = queryItemList.iterator(); i$.hasNext(); ) {
				queryItem = (IndexQueryResponse.QueryItem)i$.next();
				for (KeyedStanzasType keyedStanzas : queryItem.getKeyedStanzas()) {
					totalDocCount++;
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						GroupRole currentGroupRole = null;
						try {
							currentGroupRole = (GroupRole)unmarshaller.unmarshal(docElement);
							roleDocIds.add(Long.valueOf(currentGroupRole.getRoleDocId()));
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityGroupRole RetrieveGroupRoleDocIds unmarshal"), e);
						}
						continue;
					}
					bookmark = queryItem.getPaging().getBookmark();
				}
			}
		}
		while (!"".equals(bookmark));
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR GROUP MEMBERS = " + totalDocCount));
		return roleDocIds;
	}

	private static List<GroupRoleData> castList(List<SecurityDataBaseClass> tempList) {
		List<GroupRoleData> list = new ArrayList(tempList.size());
		for (SecurityDataBaseClass base : tempList) {
			list.add((GroupRoleData)base);
		}
		return list;
	}

	public static List<GroupRoleData> getRoleDataGroupInfo(long roleKey)
			throws EscDaoException {
		List<SecurityDataBaseClass> dataList = cdsClient.indexQuery("/groupRole/@RoleDocId", CdsClient.QUERY_COMPARE.equals, Long.toString(roleKey), "authZ", CdsSecurityBase.STANZAS.groupRole, "authZ", CdsSecurityBase.STANZAS.groupRole, true);
		return castList(dataList);
	}

	public static GroupRoleData processGroupRoleStanza(long docId, KeyedStanzasType.Stanza groupStanza) {
		GroupRole groupRole = null;
		GroupRoleData groupRoleData = null;
		try {
			Element docElement = groupStanza.getAny();
			groupRole = (GroupRole)cdsAuthZUnmarshaller.unmarshal(docElement);
			if (groupRole != null) {
				groupRoleData = new GroupRoleData();
				groupRoleData.setDocId(docId);
				groupRoleData.setGroupNm(groupRole.getGroupName());
				groupRoleData.setRoleDocId(groupRole.getRoleDocId());
				groupRoleData.setAssignedBy(groupRole.getAssignedBy());
				groupRoleData.setDateAssigned(groupRole.getDateAssigned().toGregorianCalendar());
			}
			else {
				logger.info(new FedExLogEntry("Group Role is null after unmarshalling Stanza for DocId " + docId));
			}
		}
		catch (Exception e) {
			logger.error(new FedExLogEntry("Error processing Group Role Stanza for DocId " + docId), e);
			groupRoleData = null;
		}
		return groupRoleData;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\cds\CdsSecurityGroupRole.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */