package com.fedex.cds;

import com.fedex.cds.plugin.jaxb.ApplicationRole;
import com.fedex.cds.plugin.jaxb.GroupRole;
import com.fedex.cds.plugin.jaxb.RoleList;
import com.fedex.cds.plugin.jaxb.UserRole;
import com.fedex.common.icefaces.util.FacesUtils;
import com.fedex.ea.framework.securityapi.dao.esc.EscDaoException;
import com.fedex.enterprise.security.action.ActionData;
import com.fedex.enterprise.security.esc.view.model.DataBean;
import com.fedex.enterprise.security.esc.view.model.WssoHandler;
import com.fedex.enterprise.security.resource.ResourceData;
import com.fedex.enterprise.security.role.AppRoleData;
import com.fedex.enterprise.security.role.GroupRoleData;
import com.fedex.enterprise.security.role.RoleData;
import com.fedex.enterprise.security.role.UserRoleData;
import com.fedex.enterprise.security.role.restriction.RestrictionData;
import com.fedex.enterprise.security.rule.RuleData;
import com.fedex.enterprise.security.utils.EscUtils;
import com.fedex.enterprise.security.utils.LDAPUserRecord;
import com.fedex.enterprise.security.utils.SecurityDataBaseClass;
import com.fedex.framework.cds.EnrichedQueryRequest;
import com.fedex.framework.cds.EnrichedQueryResponse;
import com.fedex.framework.cds.IndexElementType;
import com.fedex.framework.cds.IndexQueryRequest;
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
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class CdsSecurityRole
		extends CdsSecurityBase {
	private static final String EQUALS = "equals";
	private static final String CAUGHT_GENERAL_EXCEPTION_EX = "Caught general Exception ex: ";
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(CdsSecurityRole.class);

	public static long Insert(RoleData newObject) {
		return Insert(newObject, false);
	}

	public static long Insert(RoleData newObject, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		if (!systemOverride) {
			WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
			onBehalfOf = roleHandler.getUserId();
		}
		return Insert(newObject, systemOverride, onBehalfOf, "");
	}

	public static long Insert(RoleData newObject, boolean systemOverride, String onBehalfOf, String appId) {
		List<Document> request = new ArrayList();
		try {
			com.fedex.enterprise.security.cds.authZ.ObjectFactory securityObjectFactory = new com.fedex.enterprise.security.cds.authZ.ObjectFactory();
			JAXBContext propJaxbContext = JAXBContext.newInstance("com.fedex.enterprise.security.cds.authZ");
			Marshaller propMarshaller = propJaxbContext.createMarshaller();
			com.fedex.enterprise.security.cds.authZ.Role cdsRole = securityObjectFactory.createRole();
			String description = newObject.getRoleDesc();
			if ((description == null) || (description.isEmpty())) {
				description = "NA";
			}
			cdsRole.setRoleDesc(description);
			cdsRole.setRoleName(newObject.getRoleNm());
			String type = newObject.getRoleTypeCd();
			cdsRole.setRoleScopeType(type);
			if ("Application".equals(type)) {
				cdsRole.setRoleScopeName(newObject.getAppId());
			}
			else {
				cdsRole.setRoleScopeName(newObject.getRoleScopeNm());
			}
			cdsRole.setDomain("authZ");
			cdsRole.setMajorVersion(STANZA_DESC_MAJOR_VER);
			cdsRole.setMinorVersion(STANZA_DESC_MINOR_VER);
			Document doc = BuildDocument();
			propMarshaller.marshal(cdsRole, doc);
			request.add(doc);
			String callingApp = "";
			if (EscUtils.isNullOrBlank(appId)) {
				callingApp = "4112";
			}
			else {
				callingApp = appId;
			}
			String desc = newObject.getRoleNm() + " was created by " + onBehalfOf + " from " + (callingApp.equals("4112") ? "the ESC." : new StringBuilder().append("App #").append(callingApp).toString());
			InsertRequest.InsertItem auditRecord = createStaticAuditRecord(cdsRole.getRoleScopeName(), onBehalfOf, desc, "create", "role");
			List<InsertRequest.InsertItem> auditRecords = new ArrayList();
			auditRecords.add(auditRecord);
			List<Long> keys = cdsClient.insert(request, auditRecords, systemOverride);
			newObject.setDocId(keys.get(0).longValue());
			if ((cdsRole.getRoleScopeName().equals("4112")) && (!cdsRole.getRoleName().equals("*"))) {
				String newRes = cdsRole.getRoleScopeName() + "/ROLE/" + cdsRole.getRoleName() + "/";
				ResourceData resource = new ResourceData();
				resource.setAppId("4112");
				resource.setResDesc("Autocreated resource to allow self managing of the role");
				resource.setResName(newRes);
				resource.setRootFlg('N');
				logger.info(new FedExLogEntry("Creating new resource to protect the Role: " + resource.toString()));
				CdsSecurityResource cdsSecurityResource = new CdsSecurityResource();
				resource.setDocId(cdsSecurityResource.insertResource(resource, true));
				DataBean dataBean = null;
				try {
					if (FacesUtils.getManagedBean("dataBean") != null) {
						dataBean = (DataBean)FacesUtils.getManagedBean("dataBean");
					}
				}
				catch (NullPointerException npe) {
					logger.trace(new FedExLogEntry("Null pointer exception was thrown by Faces Utils."));
				}
				finally {
					Long actionDocId;
					Map<Long, ActionData> actionMap;
					actionDocId = Long.valueOf(0L);
					if (dataBean != null) {
						actionMap = dataBean.getActions();
						for (Long key : actionMap.keySet()) {
							ActionData action = actionMap.get(key);
							if (action.getActionNm().equals("manage")) {
								logger.info(new FedExLogEntry("Found the 'manage' action: " + action.toString()));
								actionDocId = key;
								break;
							}
						}
					}
					if (actionDocId.longValue() == 0L) {
						CdsSecurityAction cdsSecurityAction = new CdsSecurityAction();
						List<ActionData> actions = cdsSecurityAction.getActionsForApplicationByPartialActionName("4112", "manage", new Bookmark());
						if ((actions != null) && (!actions.isEmpty())) {
							logger.info(new FedExLogEntry("Had to look up the 'manage' action: " + actions.get(0).toString()));
							actionDocId = Long.valueOf(actions.get(0).getDocId());
						}
					}
					RuleData rule = new RuleData();
					rule.setActionDocId(actionDocId.longValue());
					rule.setResDocId(resource.getDocId());
					rule.setRoleDocId(newObject.getDocId());
					rule.setAppId("4112");
					rule.setGrantFlg('Y');
					logger.info(new FedExLogEntry("Inserting this rule to allow self managing for a role: " + rule.toString()));
					CdsSecurityRule.Insert(rule, true);
					UserRoleData userRoleData = new UserRoleData();
					userRoleData.setEmpNbr(onBehalfOf);
					userRoleData.setRoleDocId(newObject.getDocId());
					logger.info(new FedExLogEntry("Adding the user " + onBehalfOf + " to allow for managing for the role: " + cdsRole.toString()));
					long userAdd = CdsSecurityUserRole.Insert(userRoleData, newObject.getDocId(), true);
					if (userAdd > 0L) {
						logger.info(new FedExLogEntry("----User " + onBehalfOf + " was added to the managing for the role: " + cdsRole.toString()));
					}
				}
			}
		}
		catch (SoapFaultClientException sfx) {
			throw sfx;
		}
		catch (JAXBException jbEx) {
			logger.warn(new FedExLogEntry("Caught JAXB Exception ex: " + jbEx.toString()));
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Caught general Exception ex: " + e.toString()));
		}
		return newObject.getDocId();
	}

	public static void Update(RoleData newObject) {
		Update(newObject, false);
	}

	public static void Update(RoleData newObject, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		if (!systemOverride) {
			WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
			onBehalfOf = roleHandler.getUserId();
		}
		Update(newObject, false, onBehalfOf, "");
	}

	public static void Update(RoleData newObject, boolean systemOverride, String onBehalfOf, String appId) {
		String callingApp = "";
		if (EscUtils.isNullOrBlank(appId)) {
			callingApp = "4112";
		}
		else {
			callingApp = appId;
		}
		HashMap<String, String> xpathList = new HashMap();
		String description = newObject.getRoleDesc();
		if ((description == null) || (description.isEmpty())) {
			description = "NA";
		}
		xpathList.put("/role/@RoleDesc", description);
		xpathList.put("/role/@RoleScopeType", newObject.getRoleTypeCd());
		xpathList.put("/role/@RoleScopeName", newObject.getRoleScopeNm());
		String desc = newObject.getRoleNm() + " was modified by " + onBehalfOf + " from " + (callingApp.equals("4112") ? "the ESC." : new StringBuilder().append("App #").append(callingApp).toString());
		InsertRequest.InsertItem auditRecord = createStaticAuditRecord(newObject.getRoleScopeNm(), onBehalfOf, desc, "modify", "role");
		cdsClient.update(xpathList, newObject.getDocId(), "authZ", "role", auditRecord, systemOverride);
	}

	public static RoleData Retrieve(long docId) {
		return Retrieve(docId, true);
	}

	public static RoleData Retrieve(long docId, boolean loadMembers) {
		Unmarshaller unmarshaller = null;
		JAXBContext extRefStanzaContext = null;
		RoleData roleData = null;
		try {
			extRefStanzaContext = JAXBContext.newInstance(com.fedex.enterprise.security.cds.authZ.Role.class);
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRole Update new instance "), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		try {
			unmarshaller = extRefStanzaContext.createUnmarshaller();
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRole Update create unmarshaller "), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		try {
			List<Long> keys = new ArrayList();
			keys.add(Long.valueOf(docId));
			KeyQueryRequest request = buildKeyQueryRequest(keys, "role");
			KeyQueryResponse response = cdsClient.keyQuery(request);
			for (Iterator i$ = response.getKeyedStanzas().iterator(); i$.hasNext(); ) {
				KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
				List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
				for (KeyedStanzasType.Stanza s : stanzaList) {
					Element docElement = s.getAny();
					com.fedex.enterprise.security.cds.authZ.Role currentRole = null;
					try {
						currentRole = (com.fedex.enterprise.security.cds.authZ.Role)unmarshaller.unmarshal(docElement);
						roleData = new RoleData();
						roleData.setRoleDesc(currentRole.getRoleDesc());
						roleData.setDocId(keyedStanzas.getKey());
						roleData.setRoleNm(currentRole.getRoleName());
						roleData.setRoleScopeNm(currentRole.getRoleScopeName());
						roleData.setRoleTypeCd(currentRole.getRoleScopeType());
						if (loadMembers) {
							roleData.setUserMemberList(CdsSecurityUserRole.Retrieve(keyedStanzas.getKey()));
							roleData.setAppMemberList(CdsSecurityAppRole.Retrieve(keyedStanzas.getKey()));
							roleData.setGroupMemberList(CdsSecurityGroupRole.Retrieve(keyedStanzas.getKey()));
							roleData.setRestrictionMemberList(CdsSecurityRestriction.RetrieveRestrictionsByRoleName(currentRole.getRoleScopeName(), currentRole.getRoleName(), null));
						}
					}
					catch (JAXBException e) {
						logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRole unmarshal "), e);
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
		return roleData;
	}

	public static List<RoleData> RetrieveAll(List<Long> docIds, boolean loadMembers) {
		return RetrieveAll(docIds, loadMembers, true);
	}

	public static List<RoleData> retrieveWithChildrenWithoutRestrictions(List<Long> roleDocIds, String ruleAppId, boolean mapObjects) throws EscDaoException {
		IndexQueryRequest.QueryItem roleQueryItem = CdsClient.createIndexQueryItem("/rule/@ApplicationId", CdsClient.QUERY_COMPARE.equals, ruleAppId, "authZ", CdsSecurityBase.STANZAS.rule, "authZ", CdsSecurityBase.STANZAS.role);
		IndexQueryRequest.QueryItem appRoleQueryItem = CdsClient.createIndexQueryItem("/rule/@ApplicationId", CdsClient.QUERY_COMPARE.equals, ruleAppId, "authZ", CdsSecurityBase.STANZAS.rule, "authZ", CdsSecurityBase.STANZAS.applicationRole);
		IndexQueryRequest.QueryItem groupRoleQueryItem = CdsClient.createIndexQueryItem("/rule/@ApplicationId", CdsClient.QUERY_COMPARE.equals, ruleAppId, "authZ", CdsSecurityBase.STANZAS.rule, "authZ", CdsSecurityBase.STANZAS.groupRole);
		IndexQueryRequest.QueryItem userRoleQueryItem = CdsClient.createIndexQueryItem("/rule/@ApplicationId", CdsClient.QUERY_COMPARE.equals, ruleAppId, "authZ", CdsSecurityBase.STANZAS.rule, "authZ", CdsSecurityBase.STANZAS.userRole);
		IndexQueryRequest indexQueryRequest = CdsClient.createIndexQuery(new ArrayList(Arrays.asList(roleQueryItem, appRoleQueryItem, groupRoleQueryItem, userRoleQueryItem)));
		List<SecurityDataBaseClass> dataList = cdsClient.indexQuery(indexQueryRequest, mapObjects);
		Map<Long, RoleData> mapRoles = new HashMap();
		for (SecurityDataBaseClass data : dataList) {
			if ((data instanceof RoleData)) {
				mapRoles.put(Long.valueOf(data.getDocId()), (RoleData)data);
			}
		}
		for (SecurityDataBaseClass data : dataList) {
			if (SecurityDataBaseClass.DATA_TYPE.APP_ROLE.equals(data.getDataType())) {
				AppRoleData appRole = (AppRoleData)data;
				if (mapRoles.containsKey(Long.valueOf(appRole.getRoleDocId()))) {
					mapRoles.get(Long.valueOf(appRole.getRoleDocId())).getAppMemberList().add(appRole);
				}
			}
			else {
				if (SecurityDataBaseClass.DATA_TYPE.GROUP_ROLE.equals(data.getDataType())) {
					GroupRoleData groupRole = (GroupRoleData)data;
					if (mapRoles.containsKey(Long.valueOf(groupRole.getRoleDocId()))) {
						mapRoles.get(Long.valueOf(groupRole.getRoleDocId())).getGroupMemberList().add(groupRole);
					}
				}
				else {
					if (SecurityDataBaseClass.DATA_TYPE.USER_ROLE.equals(data.getDataType())) {
						UserRoleData userRole = (UserRoleData)data;
						if (mapRoles.containsKey(Long.valueOf(userRole.getRoleDocId()))) {
							mapRoles.get(Long.valueOf(userRole.getRoleDocId())).getUserMemberList().add(userRole);
						}
					}
				}
			}
		}
		return new ArrayList(mapRoles.values());
	}

	public static List<RoleData> RetrieveAll(List<Long> docIds, boolean loadMembers, boolean ldapAttributes) {
		Unmarshaller unmarshaller = null;
		JAXBContext extRefStanzaContext = null;
		List<RoleData> roles = new ArrayList();
		Set<String> appIdSet = new HashSet();
		try {
			extRefStanzaContext = JAXBContext.newInstance(com.fedex.enterprise.security.cds.authZ.Role.class);
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRole RetrieveAll new instance "), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		try {
			unmarshaller = extRefStanzaContext.createUnmarshaller();
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRole RetrieveAll create unmarshaller "), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		Iterator<Long> it = docIds.iterator();
		do {
			List<Long> listOfKeys = new ArrayList();
			for (int counter = 0; counter < 500; counter++) {
				if (it.hasNext()) {
					listOfKeys.add(it.next());
				}
			}
			try {
				KeyQueryRequest request = buildKeyQueryRequest(listOfKeys, "role");
				KeyQueryResponse response = cdsClient.keyQuery(request);
				for (Iterator i$ = response.getKeyedStanzas().iterator(); i$.hasNext(); ) {
					KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						com.fedex.enterprise.security.cds.authZ.Role currentRole = null;
						try {
							currentRole = (com.fedex.enterprise.security.cds.authZ.Role)unmarshaller.unmarshal(docElement);
							RoleData roleData = new RoleData();
							roleData.setRoleDesc(currentRole.getRoleDesc());
							roleData.setDocId(keyedStanzas.getKey());
							roleData.setRoleNm(currentRole.getRoleName());
							roleData.setRoleScopeNm(currentRole.getRoleScopeName());
							roleData.setRoleTypeCd(currentRole.getRoleScopeType());
							if ((!StringUtils.isNullOrBlank(currentRole.getRoleScopeName())) && (!"Enterprise".equalsIgnoreCase(currentRole.getRoleScopeName()))) {
								appIdSet.add(currentRole.getRoleScopeName());
							}
							else {
								logger.info(new FedExLogEntry("Skipping retreiving restrictions for realm role" + currentRole.getRoleScopeName()));
							}
							roles.add(roleData);
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRole RetrieveAll unmarshal "), e);
						}
						continue;
					}
				}
				if (loadMembers) {
					Map<Long, List<RestrictionData>> restrictionDataMap = new HashMap();
					for (String appId : appIdSet) {
						List<RestrictionData> restrictionDataList = CdsSecurityRestriction.RetrieveRoleRestrictions(null, appId);
						for (RestrictionData restrictionData : restrictionDataList) {
							if (!restrictionDataMap.containsKey(Long.valueOf(restrictionData.getRoleDocId()))) {
								restrictionDataMap.put(Long.valueOf(restrictionData.getRoleDocId()), new ArrayList());
							}
							restrictionDataMap.get(Long.valueOf(restrictionData.getRoleDocId())).add(restrictionData);
						}
					}
					for (RoleData roleData : roles) {
						roleData.setUserMemberList(CdsSecurityUserRole.Retrieve(roleData.getDocId(), ldapAttributes));
						roleData.setAppMemberList(CdsSecurityAppRole.Retrieve(roleData.getDocId(), ldapAttributes));
						roleData.setGroupMemberList(CdsSecurityGroupRole.Retrieve(roleData.getDocId()));
						if (restrictionDataMap.containsKey(Long.valueOf(roleData.getDocId()))) {
							roleData.setRestrictionMemberList(restrictionDataMap.get(Long.valueOf(roleData.getDocId())));
						}
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
		}
		while (it.hasNext());
		return roles;
	}

	public static Map<Long, String> retrieveNames(List<Long> keys) throws EscDaoException {
		HashMap<Long, String> list = new HashMap();
		List<RoleData> roleDataList = retrieve(keys, true);
		for (RoleData roleData : roleDataList) {
			list.put(Long.valueOf(roleData.getDocId()), roleData.getRoleNm());
		}
		return list;
	}

	public static List<RoleData> retrieve(List<Long> keys, boolean mapObjects) throws EscDaoException {
		return castList(cdsClient.keyQuery(keys, "authZ", CdsSecurityBase.STANZAS.role, mapObjects));
	}

	private static List<RoleData> castList(List<SecurityDataBaseClass> tempList) {
		List<RoleData> list = new ArrayList(tempList.size());
		for (SecurityDataBaseClass base : tempList) {
			list.add((RoleData)base);
		}
		return list;
	}

	public static Map<Long, String> getRoleNamesByKeys(List<Long> docIds) {
		if ((docIds == null) || (docIds.isEmpty())) {
			return Collections.emptyMap();
		}
		Unmarshaller unmarshaller = null;
		JAXBContext extRefStanzaContext = null;
		try {
			extRefStanzaContext = JAXBContext.newInstance(com.fedex.enterprise.security.cds.authZ.Role.class);
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRole getRoleNamesByKeys new instance "), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		try {
			unmarshaller = extRefStanzaContext.createUnmarshaller();
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRole getRoleNamesByKeys create unmarshaller "), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		HashMap<Long, String> roleList = new HashMap();
		Iterator<Long> it = docIds.iterator();
		do {
			List<Long> listOfKeys = new ArrayList();
			for (int counter = 0; counter < 500; counter++) {
				if (it.hasNext()) {
					listOfKeys.add(it.next());
				}
			}
			try {
				KeyQueryRequest request = buildKeyQueryRequest(listOfKeys, "role");
				KeyQueryResponse response = cdsClient.keyQuery(request);
				for (Iterator i$ = response.getKeyedStanzas().iterator(); i$.hasNext(); ) {
					KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						com.fedex.enterprise.security.cds.authZ.Role currentRole = null;
						try {
							currentRole = (com.fedex.enterprise.security.cds.authZ.Role)unmarshaller.unmarshal(docElement);
							roleList.put(Long.valueOf(keyedStanzas.getKey()), currentRole.getRoleName());
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRole getRoleNamesByKeys unmarshal "), e);
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
		}
		while (it.hasNext());
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR ROLE NAMES = " + roleList.size()));
		return roleList;
	}

	public static List<RoleData> RetrieveByAppId(String appId, Bookmark bookmarkId) {
		return RetrieveByAppId(appId, true, true, bookmarkId);
	}

	public static List<RoleData> RetrieveByAppId(String appId, boolean loadMembers, boolean ldapAttribs, Bookmark bookmarkId) {
		String bookmark = "";
		List<RoleData> response = new ArrayList();
		int totalDocCount = 0;
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		if (bookmarkId == null) {
			bookmarkId = new Bookmark();
			bookmarkId.setBookmark("5120135");
		}
		StanzaIdType stanzaId = of.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("role");
		StanzaIdType indexStanzaId = of.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("role");
		Unmarshaller unmarshaller;
		do {
			IndexQueryResponse indexResponse = cdsClient.indexQuery(BuildIndexQuery(appId, null), stanzaId, indexStanzaId, bookmark);
			List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
			JAXBContext context = null;
			unmarshaller = null;
			try {
				context = JAXBContext.newInstance(com.fedex.enterprise.security.cds.authZ.Role.class);
				unmarshaller = context.createUnmarshaller();
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRole RetrieveByAppId new instance or create unmarshaller"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
				for (Iterator i$ = queryItem.getKeyedStanzas().iterator(); i$.hasNext(); ) {
					KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
					totalDocCount++;
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						com.fedex.enterprise.security.cds.authZ.Role currentRole = null;
						try {
							currentRole = (com.fedex.enterprise.security.cds.authZ.Role)unmarshaller.unmarshal(docElement);
							RoleData roleData = new RoleData();
							roleData.setRoleDesc(currentRole.getRoleDesc());
							roleData.setDocId(keyedStanzas.getKey());
							roleData.setRoleNm(currentRole.getRoleName());
							roleData.setRoleScopeNm(currentRole.getRoleScopeName());
							roleData.setRoleTypeCd(currentRole.getRoleScopeType());
							if (loadMembers) {
								roleData.setUserMemberList(CdsSecurityUserRole.Retrieve(keyedStanzas.getKey(), ldapAttribs));
								roleData.setAppMemberList(CdsSecurityAppRole.Retrieve(keyedStanzas.getKey(), ldapAttribs));
								roleData.setGroupMemberList(CdsSecurityGroupRole.Retrieve(keyedStanzas.getKey()));
								roleData.setRestrictionMemberList(CdsSecurityRestriction.RetrieveRestrictionsByRoleName(currentRole.getRoleScopeName(), currentRole.getRoleName(), null));
							}
							response.add(roleData);
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRole RetrieveByAppId unmarshal"), e);
						}
						continue;
					}
				}
				bookmark = queryItem.getPaging().getBookmark();
			}
		}
		while ((!"".equals(bookmark)) && (bookmarkId.getBookmark() == "5120135"));
		bookmarkId.setBookmark(bookmark);
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR APPLICATION ROLES = " + totalDocCount + " for App Id: " + appId));
		return response;
	}

	public static RoleData RetrieveByRoleName(String roleName, String appId, boolean loadMembers, boolean ldapAttribs, Bookmark bookmarkId) {
		String bookmark = "";
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		if (bookmarkId == null) {
			bookmarkId = new Bookmark();
			bookmarkId.setBookmark("5120135");
		}
		StanzaIdType stanzaId = of.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("role");
		StanzaIdType indexStanzaId = of.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("role");
		RoleData roleData = new RoleData();
		Unmarshaller unmarshaller;
		do {
			IndexQueryResponse indexResponse = cdsClient.indexQuery(BuildIndexQuery(appId, roleName), stanzaId, indexStanzaId, bookmark);
			List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
			JAXBContext context = null;
			unmarshaller = null;
			try {
				context = JAXBContext.newInstance(com.fedex.enterprise.security.cds.authZ.Role.class);
				unmarshaller = context.createUnmarshaller();
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRole RetrieveByRoleName new instance or create unmarshaller"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
				for (Iterator i$ = queryItem.getKeyedStanzas().iterator(); i$.hasNext(); ) {
					KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						com.fedex.enterprise.security.cds.authZ.Role currentRole = null;
						try {
							currentRole = (com.fedex.enterprise.security.cds.authZ.Role)unmarshaller.unmarshal(docElement);
							roleData.setRoleDesc(currentRole.getRoleDesc());
							roleData.setDocId(keyedStanzas.getKey());
							roleData.setRoleNm(currentRole.getRoleName());
							roleData.setRoleScopeNm(currentRole.getRoleScopeName());
							roleData.setRoleTypeCd(currentRole.getRoleScopeType());
							if (loadMembers) {
								roleData.setUserMemberList(CdsSecurityUserRole.Retrieve(keyedStanzas.getKey(), ldapAttribs));
								roleData.setAppMemberList(CdsSecurityAppRole.Retrieve(keyedStanzas.getKey(), ldapAttribs));
								roleData.setGroupMemberList(CdsSecurityGroupRole.Retrieve(keyedStanzas.getKey()));
								roleData.setRestrictionMemberList(CdsSecurityRestriction.RetrieveRestrictionsByRoleName(currentRole.getRoleScopeName(), currentRole.getRoleName(), null));
							}
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRole RetrieveByRoleName unmarshal"), e);
						}
						continue;
					}
				}
				bookmark = queryItem.getPaging().getBookmark();
			}
		}
		while ((!"".equals(bookmark)) && (bookmarkId.getBookmark() == "5120135"));
		bookmarkId.setBookmark(bookmark);
		return roleData;
	}

	public static List<RoleData> RetrieveTheAnyoneRole() {
		String bookmark = "";
		List<RoleData> response = new ArrayList();
		int totalDocCount = 0;
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		Bookmark bookmarkId = new Bookmark();
		bookmarkId.setBookmark("5120135");
		StanzaIdType stanzaId = of.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("role");
		StanzaIdType indexStanzaId = of.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("role");
		Unmarshaller unmarshaller;
		do {
			IndexQueryResponse indexResponse = cdsClient.indexQuery(BuildAnyoneQuery(), stanzaId, indexStanzaId, bookmark);
			List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
			JAXBContext context = null;
			unmarshaller = null;
			try {
				context = JAXBContext.newInstance(com.fedex.enterprise.security.cds.authZ.Role.class);
				unmarshaller = context.createUnmarshaller();
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRole RetrieveTheAnyoneRole new instance or create unmarshaller"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
				for (Iterator i$ = queryItem.getKeyedStanzas().iterator(); i$.hasNext(); ) {
					KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
					totalDocCount++;
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						com.fedex.enterprise.security.cds.authZ.Role currentRole = null;
						try {
							currentRole = (com.fedex.enterprise.security.cds.authZ.Role)unmarshaller.unmarshal(docElement);
							RoleData roleData = new RoleData();
							roleData.setRoleDesc(currentRole.getRoleDesc());
							roleData.setDocId(keyedStanzas.getKey());
							roleData.setRoleNm(currentRole.getRoleName());
							roleData.setRoleScopeNm(currentRole.getRoleScopeName());
							roleData.setRoleTypeCd(currentRole.getRoleScopeType());
							response.add(roleData);
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRole RetrieveTheAnyoneRole unmarshal"), e);
						}
						continue;
					}
				}
				bookmark = queryItem.getPaging().getBookmark();
			}
		}
		while ((!"".equals(bookmark)) && (bookmarkId.getBookmark() == "5120135"));
		bookmarkId.setBookmark(bookmark);
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR THE ANYONE ROLE = " + totalDocCount + " for App Id: " + "4112"));
		return response;
	}

	public static List<RoleData> RetrieveRolesForAdmin(String appId, Bookmark bookmarkId) {
		return RetrieveRolesForAdmin(appId, true, bookmarkId);
	}

	public static List<RoleData> RetrieveRolesForAdmin(String appId, boolean loadMembers, Bookmark bookmarkId) {
		String bookmark = "";
		List<RoleData> response = new ArrayList();
		int totalDocCount = 0;
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		if (bookmarkId == null) {
			bookmarkId = new Bookmark();
			bookmarkId.setBookmark("5120135");
		}
		StanzaIdType stanzaId = of.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("role");
		StanzaIdType indexStanzaId = of.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("role");
		Unmarshaller unmarshaller;
		do {
			IndexQueryResponse indexResponse = cdsClient.indexQuery(BuildRoleTypeIndexQuery("Realm"), stanzaId, indexStanzaId, bookmark);
			List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
			JAXBContext context = null;
			unmarshaller = null;
			try {
				context = JAXBContext.newInstance(com.fedex.enterprise.security.cds.authZ.Role.class);
				unmarshaller = context.createUnmarshaller();
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRole RetrieveRolesForAdmin new instance or create unmarshaller"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
				for (Iterator i$ = queryItem.getKeyedStanzas().iterator(); i$.hasNext(); ) {
					KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
					totalDocCount++;
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						com.fedex.enterprise.security.cds.authZ.Role currentRole = null;
						try {
							currentRole = (com.fedex.enterprise.security.cds.authZ.Role)unmarshaller.unmarshal(docElement);
							RoleData roleData = new RoleData();
							roleData.setRoleDesc(currentRole.getRoleDesc());
							roleData.setDocId(keyedStanzas.getKey());
							roleData.setRoleNm(currentRole.getRoleName());
							roleData.setRoleScopeNm(currentRole.getRoleScopeName());
							roleData.setRoleTypeCd(currentRole.getRoleScopeType());
							if (loadMembers) {
								roleData.setUserMemberList(CdsSecurityUserRole.Retrieve(keyedStanzas.getKey()));
								roleData.setAppMemberList(CdsSecurityAppRole.Retrieve(keyedStanzas.getKey()));
								roleData.setGroupMemberList(CdsSecurityGroupRole.Retrieve(keyedStanzas.getKey()));
								roleData.setRestrictionMemberList(CdsSecurityRestriction.RetrieveRestrictionsByRoleName(currentRole.getRoleScopeName(), currentRole.getRoleName(), null));
							}
							response.add(roleData);
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRole RetrieveRolesForAdmin unmarshal"), e);
						}
						continue;
					}
				}
				bookmark = queryItem.getPaging().getBookmark();
			}
		}
		while ((!"".equals(bookmark)) && (bookmarkId.getBookmark() == "5120135"));
		bookmarkId.setBookmark(bookmark);
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR REALM ROLES = " + totalDocCount + "***"));
		response.addAll(RetrieveByAppId(appId, loadMembers, true, null));
		return response;
	}

	public static List<RoleData> RetrieveByNames(String appId) {
		logger.info(new FedExLogEntry("Retrieve Roles for appId by Name " + appId));
		if (cdsClient == null) {
			logger.warn(new FedExLogEntry("cdsClient is null! "));
		}
		List<RoleData> response = new ArrayList();
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		DocumentBuilder builder;
		try {
			builder = factory.newDocumentBuilder();
		}
		catch (ParserConfigurationException e) {
			logger.error(new FedExLogEntry("Caught ParserConfigurationException in CdsSecurityRole RetrieveByNames new document builder"), e);
			throw new RuntimeException(e.getMessage(), e);
		}
		Document document = builder.newDocument();
		Element root = document.createElement("ApplicationId");
		root.setTextContent(appId);
		document.appendChild(root);
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		EnrichedQueryRequest enrichedRequest = of.createEnrichedQueryRequest();
		enrichedRequest.setDomain("authZ");
		enrichedRequest.setName("getRoles");
		enrichedRequest.setAny(document.getDocumentElement());
		EnrichedQueryResponse enrichedResponse = cdsClient.enrichedQuery(enrichedRequest);
		JAXBContext propertiesStanzaContext = null;
		Unmarshaller unmarshaller = null;
		try {
			propertiesStanzaContext = JAXBContext.newInstance(RoleList.class);
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRole RetrieveByNames create new instance"), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		try {
			unmarshaller = propertiesStanzaContext.createUnmarshaller();
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRole RetrieveByNames create unmarshaller"), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		List<Object> objects = enrichedResponse.getAny();
		Element docElement = (Element)objects.get(0);
		com.fedex.cds.plugin.jaxb.ObjectFactory objectProperty = new com.fedex.cds.plugin.jaxb.ObjectFactory();
		RoleList roleList = objectProperty.createRoleList();
		try {
			roleList = (RoleList)unmarshaller.unmarshal(docElement);
		}
		catch (JAXBException e) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRole RetrieveByNames create unmarshal"), e);
		}
		List<com.fedex.cds.plugin.jaxb.Role> roles = roleList.getRole();
		logger.warn(new FedExLogEntry("TOTAL  ROLES RECEIVED FROM ENRICHED QUERY RESPONSE = " + roles.size()));
		for (com.fedex.cds.plugin.jaxb.Role role : roles) {
			RoleData newRole = new RoleData();
			newRole.setDocId(role.getRoleDocId());
			newRole.setRoleNm(role.getRoleName());
			newRole.setRoleDesc(role.getRoleDesc());
			newRole.setRoleScopeNm(role.getRoleScopeName());
			newRole.setRoleTypeCd(role.getRoleScopeType());
			if ((role.getAppMemberList() != null) && (!role.getAppMemberList().isEmpty())) {
				List<AppRoleData> appRoleList = new ArrayList();
				for (ApplicationRole app : role.getAppMemberList()) {
					AppRoleData newAppRoleData = new AppRoleData();
					newAppRoleData.setAppId(Long.toString(app.getApplicationId()));
					newAppRoleData.setDocId(app.getDocId());
					newAppRoleData.setRoleDocId(app.getRoleDocId());
					if (app.getDateAssigned() != null) {
						newAppRoleData.setDateAssigned(app.getDateAssigned().toGregorianCalendar());
					}
					newAppRoleData.setAssignedBy(app.getAssignedBy());
					LDAPUserRecord record = ldapSearch.getUserAttribs("APP" + newAppRoleData.getAppId());
					newAppRoleData.setApplicationName(record.getLastName());
					appRoleList.add(newAppRoleData);
				}
				newRole.setAppMemberList(appRoleList);
			}
			if ((role.getUserMemberList() != null) && (!role.getUserMemberList().isEmpty())) {
				List<UserRoleData> userMemberList = new ArrayList();
				for (UserRole user : role.getUserMemberList()) {
					UserRoleData newUserRoleData = new UserRoleData();
					newUserRoleData.setEmpNbr(user.getUserFedExId());
					newUserRoleData.setDocId(user.getDocId());
					newUserRoleData.setRoleDocId(user.getRoleDocId());
					if (user.getDateAssigned() != null) {
						newUserRoleData.setDateAssigned(user.getDateAssigned().toGregorianCalendar());
					}
					newUserRoleData.setAssignedBy(user.getAssignedBy());
					LDAPUserRecord record = ldapSearch.getUserAttribs(newUserRoleData.getEmpNbr());
					logger.info(new FedExLogEntry("Record returned from LDAP: " + record));
					if ((record.getNickName() != null) && (!"".equals(record.getNickName().trim()))) {
						newUserRoleData.setFirstName(record.getNickName());
					}
					else {
						newUserRoleData.setFirstName(record.getFirstName());
					}
					newUserRoleData.setLastName(record.getLastName());
					userMemberList.add(newUserRoleData);
				}
				newRole.setUserMemberList(userMemberList);
			}
			if ((role.getGroupMemberList() != null) && (!role.getGroupMemberList().isEmpty())) {
				List<GroupRoleData> groupMemberList = new ArrayList();
				for (GroupRole group : role.getGroupMemberList()) {
					GroupRoleData newGroupRoleData = new GroupRoleData();
					newGroupRoleData.setDocId(group.getDocId());
					newGroupRoleData.setRoleDocId(group.getRoleDocId());
					if (group.getDateAssigned() != null) {
						newGroupRoleData.setDateAssigned(group.getDateAssigned().toGregorianCalendar());
					}
					newGroupRoleData.setAssignedBy(group.getAssignedBy());
					newGroupRoleData.setGroupNm(group.getGroupName());
					groupMemberList.add(newGroupRoleData);
				}
				newRole.setGroupMemberList(groupMemberList);
			}
			response.add(newRole);
		}
		logger.info(new FedExLogEntry("Retrive Roles By Names Returned " + response.size() + " roles."));
		return response;
	}

	private static List<IndexElementType> BuildIndexQuery(String appID, String roleName) {
		List<IndexElementType> indexElements = new ArrayList();
		IndexElementType appId = new IndexElementType();
		appId.setXpath("/role/@RoleScopeName");
		appId.setComparison("equals");
		appId.setValue(appID);
		indexElements.add(appId);
		if ((roleName != null) && (!roleName.equalsIgnoreCase(""))) {
			IndexElementType role = new IndexElementType();
			role.setXpath("/role/@RoleName");
			role.setComparison("equals");
			role.setValue(roleName);
			indexElements.add(role);
		}
		return indexElements;
	}

	private static List<IndexElementType> BuildRoleTypeIndexQuery(String roleType) {
		List<IndexElementType> indexElements = new ArrayList();
		IndexElementType appId = new IndexElementType();
		appId.setXpath("/role/@RoleScopeType");
		appId.setComparison("equals");
		appId.setValue(roleType);
		indexElements.add(appId);
		return indexElements;
	}

	private static List<IndexElementType> BuildAnyoneQuery() {
		List<IndexElementType> indexElements = new ArrayList();
		IndexElementType appId = new IndexElementType();
		appId.setXpath("/role/@RoleScopeName");
		appId.setComparison("equals");
		appId.setValue("4112");
		indexElements.add(appId);
		IndexElementType roleName = new IndexElementType();
		roleName.setXpath("/role/@RoleName");
		roleName.setComparison("equals");
		roleName.setValue("*");
		indexElements.add(roleName);
		return indexElements;
	}

	public RoleData retrieveRoleDataByRoleName(String roleName, String appId)
			throws EscDaoException {
		RoleData roleData = null;
		List<SecurityDataBaseClass> dataList = cdsClient.indexQuery("/role/@RoleScopeName", CdsClient.QUERY_COMPARE.equals, appId, "/role/@RoleName", CdsClient.QUERY_COMPARE.equals, roleName, "authZ", CdsSecurityBase.STANZAS.role, "authZ", CdsSecurityBase.STANZAS.role, true);
		if ((dataList == null) || (dataList.isEmpty())) {
			logger.warn("Unable to find role in CDS, name: " + roleName + ", app: " + appId);
			throw new EscDaoException("Unable to find role in CDS, name: " + roleName + ", app: " + appId);
		}
		if (dataList.size() > 1) {
			logger.warn("Found duplicate roles in CDS, name: " + roleName + ", app: " + appId);
			throw new EscDaoException("Found duplicate roles in CDS, name: " + roleName + ", app: " + appId);
		}
		roleData = (RoleData)dataList.get(0);
		roleData.setGroupMemberList(CdsSecurityGroupRole.getRoleDataGroupInfo(roleData.getDocId()));
		roleData.setAppMemberList(CdsSecurityAppRole.getRoleDataAppInfo(roleData.getDocId()));
		roleData.setRestrictionMemberList(CdsSecurityRestriction.getRoleDataRestrictionInfo(roleName, appId));
		roleData.setUserMemberList(CdsSecurityUserRole.getRoleDataUserInfo(roleData.getDocId()));
		return roleData;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\cds\CdsSecurityRole.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */