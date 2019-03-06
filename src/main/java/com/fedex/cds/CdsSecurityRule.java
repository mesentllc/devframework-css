package com.fedex.cds;

import com.fedex.cds.plugin.jaxb.CustomAuthZClass;
import com.fedex.cds.plugin.jaxb.ExtendedRule;
import com.fedex.cds.plugin.jaxb.RuleList;
import com.fedex.common.icefaces.util.FacesUtils;
import com.fedex.ea.framework.securityapi.dao.esc.EscDaoException;
import com.fedex.enterprise.security.action.ActionData;
import com.fedex.enterprise.security.cds.authZ.AuditRecord;
import com.fedex.enterprise.security.customauthz.CustomAuthzData;
import com.fedex.enterprise.security.esc.view.model.WssoHandler;
import com.fedex.enterprise.security.rule.ExtendedRuleData;
import com.fedex.enterprise.security.rule.ExtendedRuleXrefData;
import com.fedex.enterprise.security.rule.RuleData;
import com.fedex.enterprise.security.utils.EscUtils;
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
import com.fedex.framework.cds.PagingRequestType;
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
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.ws.soap.SOAPFaultException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class CdsSecurityRule
		extends CdsSecurityBase {
	private static final String FROM = " from ";
	private static final String THE_ESC = "the ESC.";
	private static final String APP = "App #";
	private static final String WAS_ADDED_BY = "' was added by ";
	private static final String RULE2 = "Rule '";
	private static final String EQUALS = "equals";
	private static final Long EMPTY_VALUE = Long.valueOf(5120135L);
	private static com.fedex.enterprise.security.cds.authZ.ObjectFactory objectFactory;
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(CdsSecurityRule.class);
	private static final int ITEMS_PER_REQUEST = 200;

	public static com.fedex.enterprise.security.cds.authZ.ObjectFactory getObjectFactory() {
		return objectFactory;
	}

	public static void setObjectFactory(com.fedex.enterprise.security.cds.authZ.ObjectFactory objectFactory) {
		objectFactory = objectFactory;
	}

	public static Long Insert(RuleData newObject) {
		return Insert(newObject, false);
	}

	public static Long Insert(RuleData newObject, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		if ((!systemOverride) && (FacesContext.getCurrentInstance() != null)) {
			WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
			onBehalfOf = roleHandler.getUserId();
		}
		return Insert(newObject, systemOverride, onBehalfOf, "");
	}

	public static Long Insert(RuleData newObject, boolean systemOverride, String onBehalfOf, String appId) {
		List<Document> request = new ArrayList();
		String callingApp = "";
		if (EscUtils.isNullOrBlank(appId)) {
			callingApp = "4112";
		}
		else {
			callingApp = appId;
		}
		Long key;
		try {
			com.fedex.enterprise.security.cds.authZ.ObjectFactory securityObjectFactory = new com.fedex.enterprise.security.cds.authZ.ObjectFactory();
			JAXBContext propJaxbContext = JAXBContext.newInstance("com.fedex.enterprise.security.cds.authZ");
			Marshaller propMarshaller = propJaxbContext.createMarshaller();
			com.fedex.enterprise.security.cds.authZ.Rule rule = securityObjectFactory.createRule();
			rule.setApplicationId(Long.parseLong(newObject.getAppId()));
			rule.setDomain("authZ");
			rule.setActionDocId(newObject.getActionDocId());
			rule.setCustAuthZDocId(newObject.getCustAuthZDocId());
			if (newObject.getGrantFlg() == 'Y') {
				rule.setGrantDenyFlg(com.fedex.enterprise.security.cds.authZ.GrantDenyFlg.Y);
			}
			else {
				rule.setGrantDenyFlg(com.fedex.enterprise.security.cds.authZ.GrantDenyFlg.N);
			}
			rule.setResourceDocId(newObject.getResDocId());
			rule.setRoleDocId(newObject.getRoleDocId());
			rule.setMajorVersion(STANZA_DESC_MAJOR_VER);
			rule.setMinorVersion(STANZA_DESC_MINOR_VER);
			Document doc = BuildDocument();
			propMarshaller.marshal(rule, doc);
			request.add(doc);
			List<Long> ruleKeys = cdsClient.insert(request, null, systemOverride);
			if ((ruleKeys != null) && (!ruleKeys.isEmpty())) {
				key = ruleKeys.get(0);
			}
			else {
				logger.warn(new FedExLogEntry("WARNING: We didn't get a key back from CDS for this rule!"));
				throw new RuntimeException("Sorry, something didn't work correctly in the Datastore.");
			}
			String desc = "Rule '" + EscUtils.getRuleNameByDocId(key.longValue(), newObject.getAppId()) + "' was added by " + onBehalfOf + " from " + (callingApp.equals("4112") ? "the ESC." : new StringBuilder().append("App #").append(callingApp).toString());
			AuditRecord auditRecord = createStaticAuditRecordObject(rule.getApplicationId() + "", onBehalfOf, desc, "create", "rule");
			CdsSecurityAuditReport.Insert(auditRecord, true);
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
			throw new RuntimeException(e);
		}
		return key;
	}

	public static void Delete(RuleData objectToDelete) {
		Delete(objectToDelete, false);
	}

	public static void Delete(RuleData objectToDelete, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		if (!systemOverride) {
			WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
			onBehalfOf = roleHandler.getUserId();
		}
		Delete(objectToDelete, false, onBehalfOf, "");
	}

	public static void Delete(RuleData objectToDelete, boolean systemOverride, String onBehalfOf, String appId) {
		try {
			String callingApp = "";
			if (EscUtils.isNullOrBlank(appId)) {
				callingApp = objectToDelete.getAppId();
			}
			else {
				callingApp = appId;
			}
			List<ExtendedRuleXrefData> extRuleXRef = CdsSecurityExtRuleXRef.Retrieve(objectToDelete.getDocId(), new Bookmark());
			List<InsertRequest.InsertItem> auditRecords = new ArrayList();
			List<Long> extRuleXrefKeys = new ArrayList();
			if ((extRuleXRef != null) && (!extRuleXRef.isEmpty())) {
				for (ExtendedRuleXrefData xref : extRuleXRef) {
					String desc2 = "Extended Rule #" + xref.getDocId() + " was removed from Rule # " + objectToDelete.getDocId() + " by the ESC due to the deletion of the rule.";
					InsertRequest.InsertItem item = createStaticAuditRecord(objectToDelete.getAppId(), onBehalfOf, desc2, "delete", "extRuleXRef");
					auditRecords.add(item);
					extRuleXrefKeys.add(Long.valueOf(xref.getDocId()));
				}
			}
			try {
				if ((extRuleXrefKeys != null) && (!extRuleXrefKeys.isEmpty())) {
					CdsSecurityExtRuleXRef.Delete(extRuleXrefKeys, "extRuleXRef", auditRecords);
				}
			}
			catch (Exception e) {
				logger.warn(new FedExLogEntry("WARNING: unable to properly delete any XRefs for the rules."));
			}
			String desc = "Rule '" + EscUtils.getRuleNameByDocId(objectToDelete.getDocId(), objectToDelete.getAppId()) + "' was deleted by " + onBehalfOf + " from " + (callingApp.equals("4112") ? "the ESC." : new StringBuilder().append("App #").append(callingApp).toString());
			InsertRequest.InsertItem auditRecord = createStaticAuditRecord(callingApp, onBehalfOf, desc, "delete", "rule");
			Delete(Long.valueOf(objectToDelete.getDocId()), "rule", auditRecord, systemOverride);
		}
		catch (SOAPFaultException sfe) {
			throw new RuntimeException(sfe.getMessage(), sfe);
		}
	}

	public static void Delete(long docId) {
		Delete(docId, false);
	}

	public static void Delete(long docId, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		if ((!systemOverride) && (FacesContext.getCurrentInstance() != null)) {
			WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
			onBehalfOf = roleHandler.getUserId();
		}
		Delete(docId, systemOverride, onBehalfOf, "");
	}

	public static void Delete(long docId, boolean systemOverride, String onBehalfOf, String appId) {
		try {
			String callingApp = "";
			if (EscUtils.isNullOrBlank(appId)) {
				callingApp = "4112";
			}
			else {
				callingApp = appId;
			}
			RuleData objectToDelete = Retrieve(docId, false);
			List<ExtendedRuleXrefData> extRuleXRef = CdsSecurityExtRuleXRef.Retrieve(objectToDelete.getDocId(), new Bookmark());
			List<InsertRequest.InsertItem> auditRecords = new ArrayList();
			List<Long> extRuleXrefKeys = new ArrayList();
			if ((extRuleXRef != null) && (!extRuleXRef.isEmpty())) {
				for (ExtendedRuleXrefData xref : extRuleXRef) {
					String desc2 = "Extended Rule #" + xref.getDocId() + " was removed from Rule # " + objectToDelete.getDocId() + " by the ESC due to the deletion of the rule.";
					InsertRequest.InsertItem item = createStaticAuditRecord(objectToDelete.getAppId(), onBehalfOf, desc2, "delete", "extRuleXRef");
					auditRecords.add(item);
					extRuleXrefKeys.add(Long.valueOf(xref.getDocId()));
				}
			}
			try {
				if ((extRuleXrefKeys != null) && (!extRuleXrefKeys.isEmpty())) {
					CdsSecurityExtRuleXRef.Delete(extRuleXrefKeys, "extRuleXRef", auditRecords);
				}
			}
			catch (Exception e) {
				logger.warn(new FedExLogEntry("WARNING: unable to properly delete any XRefs for the rules."));
			}
			String desc = "Rule '" + EscUtils.getRuleNameByDocId(docId, appId) + "' was deleted by " + onBehalfOf + " from " + (callingApp.equals("4112") ? "the ESC." : new StringBuilder().append("App #").append(callingApp).toString());
			InsertRequest.InsertItem auditRecord = createStaticAuditRecord(callingApp, onBehalfOf, desc, "delete", "rule");
			Delete(Long.valueOf(docId), "rule", auditRecord, systemOverride);
		}
		catch (SOAPFaultException sfe) {
			throw new RuntimeException(sfe.getMessage(), sfe);
		}
	}

	public static IndexQueryResponse indexQuery(List<IndexElementType> indexElements, StanzaIdType stanzaId, StanzaIdType indexStanzaId) {
		com.fedex.framework.cds.ObjectFactory objectFactory = new com.fedex.framework.cds.ObjectFactory();
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
			paging.setResultsPerPage(200);
			queryItem.setPaging(paging);
			queryItems.add(queryItem);
			String bookmark = null;
			IndexQueryResponse partialResponse = cdsClient.indexQuery(indexIndexElements, stanzaId, indexStanzaId, bookmark);
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
			logger.error(new FedExLogEntry("Caught General Exception in CdsSecurityRule indexQuery"), e);
			throw new RuntimeException(e);
		}
		return queryResponse;
	}

	public static void Update(RuleData objectToUpdate) {
		Update(objectToUpdate, false);
	}

	public static void Update(RuleData objectToUpdate, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		if (!systemOverride) {
			WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
			onBehalfOf = roleHandler.getUserId();
		}
		Update(objectToUpdate, false, onBehalfOf, "");
	}

	public static void Update(RuleData objectToUpdate, boolean systemOverride, String onBehalfOf, String appId) {
		String callingApp = "";
		if (EscUtils.isNullOrBlank(appId)) {
			callingApp = "4112";
		}
		else {
			callingApp = appId;
		}
		HashMap<String, String> xpathList = new HashMap();
		xpathList.put("/rule/@ActionDocId", Long.toString(objectToUpdate.getActionDocId()));
		xpathList.put("/rule/@ResourceDocId", Long.toString(objectToUpdate.getResDocId()));
		xpathList.put("/rule/@RoleDocId", Long.toString(objectToUpdate.getRoleDocId()));
		xpathList.put("/rule/@GrantDenyFlg", Character.toString(objectToUpdate.getGrantFlg()));
		xpathList.put("/rule/@CustAuthZDocId", Long.toString(objectToUpdate.getCustAuthZDocId()));
		String desc = "Rule '" + EscUtils.getRuleNameByDocId(objectToUpdate.getDocId(), appId) + "' was modified by " + onBehalfOf + " from " + (callingApp.equals("4112") ? "the ESC." : new StringBuilder().append("App #").append(callingApp).toString());
		InsertRequest.InsertItem auditRecord = createStaticAuditRecord(objectToUpdate.getAppId(), onBehalfOf, desc, "modify", "extendedRule");
		cdsClient.update(xpathList, objectToUpdate.getDocId(), "authZ", "rule", auditRecord, systemOverride);
	}

	public static List<RuleData> Retrieve(String appId, Bookmark bookmarkId) {
		List<Long> actionIds = new ArrayList();
		List<Long> resourceIds = new ArrayList();
		List<Long> roleIds = new ArrayList();
		logger.info(new FedExLogEntry("Retrieve Rules for appId " + appId));
		if (cdsClient == null) {
			logger.warn(new FedExLogEntry("cdsClient is null! "));
		}
		String bookmark = "";
		List<RuleData> response = new ArrayList();
		int totalDocCount = 0;
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		if (bookmarkId == null) {
			bookmarkId = new Bookmark();
			bookmarkId.setBookmark("5120135");
		}
		StanzaIdType stanzaId = of.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("rule");
		StanzaIdType indexStanzaId = of.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("rule");
		Unmarshaller unmarshaller;
		do {
			IndexQueryResponse indexResponse = cdsClient.indexQuery(BuildIndexQuery(Integer.parseInt(appId), EMPTY_VALUE.longValue(), EMPTY_VALUE.longValue()), stanzaId, indexStanzaId, bookmark);
			List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
			JAXBContext propertiesStanzaContext = null;
			unmarshaller = null;
			try {
				propertiesStanzaContext = JAXBContext.newInstance(com.fedex.enterprise.security.cds.authZ.Rule.class);
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRule Retrieve new instance Rule"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			try {
				unmarshaller = propertiesStanzaContext.createUnmarshaller();
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRule Retrieve create marshaller"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
				for (Iterator i$ = queryItem.getKeyedStanzas().iterator(); i$.hasNext(); ) {
					KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
					totalDocCount++;
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						com.fedex.enterprise.security.cds.authZ.Rule currentRule = null;
						try {
							currentRule = (com.fedex.enterprise.security.cds.authZ.Rule)unmarshaller.unmarshal(docElement);
							RuleData newRuleData = new RuleData();
							newRuleData.setActionDocId(currentRule.getActionDocId());
							newRuleData.setAppId(appId);
							newRuleData.setCustAuthZDocId(currentRule.getCustAuthZDocId());
							if (currentRule.getCustAuthZDocId() != 0L) {
								newRuleData.setCustAuthzExist(true);
							}
							newRuleData.setDocId(keyedStanzas.getKey());
							if (currentRule.getGrantDenyFlg() == com.fedex.enterprise.security.cds.authZ.GrantDenyFlg.Y) {
								newRuleData.setGrantFlg('Y');
							}
							else {
								newRuleData.setGrantFlg('N');
							}
							newRuleData.setResDocId(currentRule.getResourceDocId());
							newRuleData.setRoleDocId(currentRule.getRoleDocId());
							actionIds.add(Long.valueOf(currentRule.getActionDocId()));
							resourceIds.add(Long.valueOf(currentRule.getResourceDocId()));
							roleIds.add(Long.valueOf(currentRule.getRoleDocId()));
							response.add(newRuleData);
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRule Retrieve unmarshal"), e);
						}
						continue;
					}
				}
				bookmark = queryItem.getPaging().getBookmark();
			}
		}
		while ((!"".equals(bookmark)) && (bookmarkId.getBookmark() == "5120135"));
		bookmarkId.setBookmark(bookmark);
		Map<Long, String> actionNames = CdsSecurityAction.getActionNamesByKeys(new ArrayList(new HashSet(actionIds)));
		Map<Long, String> resourceNames = CdsSecurityResource.getResourceNamesByKeys(new ArrayList(new HashSet(resourceIds)));
		Map<Long, String> roleNames = CdsSecurityRole.getRoleNamesByKeys(new ArrayList(new HashSet(roleIds)));
		List<ExtendedRuleXrefData> extendedRuleXref = CdsSecurityExtRuleXRef.Retrieve(appId, null);
		if ((extendedRuleXref != null) && (!extendedRuleXref.isEmpty())) {
			List<Long> xrefKeys = new ArrayList();
			for (ExtendedRuleXrefData xref : extendedRuleXref) {
				xrefKeys.add(Long.valueOf(xref.getExtRuleDocId()));
			}
			xrefKeys = new ArrayList(new HashSet(xrefKeys));
			List<ExtendedRuleData> xrefDataList = CdsSecurityExtendedRule.Retrieve(xrefKeys);
			Map<Long, ExtendedRuleData> mapExtRule = new HashMap();
			for (ExtendedRuleData xrefData : xrefDataList) {
				mapExtRule.put(Long.valueOf(xrefData.getDocId()), xrefData);
			}
			for (RuleData ruleData : response) {
				for (ExtendedRuleXrefData xref : extendedRuleXref) {
					if (xref.getRuleDocId() == ruleData.getDocId()) {
						if (!mapExtRule.containsKey(Long.valueOf(xref.getExtRuleDocId()))) {
							logger.always("Unable to find extended rule " + xref.getExtRuleDocId() + " for rule " + ruleData.getDocId());
						}
						else {
							if (ruleData.getExtendedRuleList() == null) {
								ruleData.setExtendedRuleList(new ArrayList());
							}
							ruleData.getExtendedRuleList().add(mapExtRule.get(Long.valueOf(xref.getExtRuleDocId())));
						}
						xrefKeys.remove(Long.valueOf(xref.getExtRuleDocId()));
					}
				}
				if (xrefKeys.isEmpty()) {
					break;
				}
			}
			if (!xrefKeys.isEmpty()) {
				logger.always("Found extra cross reference items without a rule to link to.  " + xrefKeys.toArray().toString());
			}
		}
		for (RuleData ruleData : response) {
			if (actionNames.containsKey(Long.valueOf(ruleData.getActionDocId()))) {
				ruleData.setActionNm(actionNames.get(Long.valueOf(ruleData.getActionDocId())));
			}
			else {
				logger.always("Unable to find action for action ID " + ruleData.getActionDocId() + " for rule ID " + ruleData.getDocId());
			}
			if (resourceNames.containsKey(Long.valueOf(ruleData.getResDocId()))) {
				ruleData.setResourceNm(resourceNames.get(Long.valueOf(ruleData.getResDocId())));
			}
			else {
				logger.always("Unable to find resource for resource ID " + ruleData.getResDocId() + " for rule ID " + ruleData.getDocId());
			}
			if (roleNames.containsKey(Long.valueOf(ruleData.getRoleDocId()))) {
				ruleData.setRoleNm(roleNames.get(Long.valueOf(ruleData.getRoleDocId())));
			}
			else {
				logger.always("Unable to find role for role ID " + ruleData.getRoleDocId() + " for rule ID " + ruleData.getDocId());
			}
		}
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR RULES = " + totalDocCount));
		return response;
	}

	public static List<RuleData> RetrieveByNames(String appId) {
		logger.info(new FedExLogEntry("Retrieve Rules for appId by Name " + appId));
		if (cdsClient == null) {
			logger.warn(new FedExLogEntry("cdsClient is null! "));
		}
		List<RuleData> response = new ArrayList();
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		DocumentBuilder builder;
		try {
			builder = factory.newDocumentBuilder();
		}
		catch (ParserConfigurationException e) {
			logger.error(new FedExLogEntry("Caught ParserConfigurationException in CdsSecurityRule RetrieveByNames new document builder"), e);
			throw new RuntimeException(e.getMessage(), e);
		}
		Document document = builder.newDocument();
		Element root = document.createElement("ApplicationId");
		root.setTextContent(appId);
		document.appendChild(root);
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		EnrichedQueryRequest enrichedRequest = of.createEnrichedQueryRequest();
		enrichedRequest.setDomain("authZ");
		enrichedRequest.setName("getRules");
		enrichedRequest.setAny(document.getDocumentElement());
		EnrichedQueryResponse enrichedResponse = cdsClient.enrichedQuery(enrichedRequest);
		JAXBContext propertiesStanzaContext = null;
		Unmarshaller unmarshaller = null;
		try {
			propertiesStanzaContext = JAXBContext.newInstance(RuleList.class);
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRule RetrieveByNames new instance"), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		try {
			unmarshaller = propertiesStanzaContext.createUnmarshaller();
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRule RetrieveByNames create unmarshaller"), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		List<Object> objects = enrichedResponse.getAny();
		Element docElement = (Element)objects.get(0);
		com.fedex.cds.plugin.jaxb.ObjectFactory objectProperty = new com.fedex.cds.plugin.jaxb.ObjectFactory();
		RuleList ruleList = objectProperty.createRuleList();
		try {
			ruleList = (RuleList)unmarshaller.unmarshal(docElement);
		}
		catch (JAXBException e) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRule RetrieveByNames unmarshal"), e);
		}
		List<com.fedex.cds.plugin.jaxb.Rule> rules = ruleList.getRule();
		logger.warn(new FedExLogEntry("TOTAL  RULES RECEIVED FROM ENRICHED QUERY RESPONSE = " + rules.size()));
		for (com.fedex.cds.plugin.jaxb.Rule rule : rules) {
			RuleData newRuleData = new RuleData();
			newRuleData.setActionDocId(rule.getActionDocId());
			newRuleData.setActionNm(rule.getActionName());
			newRuleData.setAppId(appId);
			newRuleData.setDocId(rule.getRuleDocId());
			if (rule.getGrantDenyFlg() == com.fedex.cds.plugin.jaxb.GrantDenyFlg.Y) {
				newRuleData.setGrantFlg('Y');
			}
			else {
				newRuleData.setGrantFlg('N');
			}
			newRuleData.setResDocId(rule.getResourceDocId());
			newRuleData.setResourceNm(rule.getResourceName());
			newRuleData.setRoleDocId(rule.getRoleDocId());
			newRuleData.setRoleNm(rule.getRoleName());
			newRuleData.setCustAuthZDocId(rule.getCustAuthZDocId().longValue());
			if ((rule.getCustAuthZDocId().longValue() != 0L) && (rule.getCustAuthZClass() != null)) {
				List<CustomAuthzData> custAuthzList = new ArrayList();
				CustomAuthzData customAuthz = new CustomAuthzData();
				CustomAuthZClass customAuthzClass = rule.getCustAuthZClass();
				customAuthz.setDocId(rule.getCustAuthZDocId().longValue());
				customAuthz.setAppId(rule.getApplicationId() + "");
				customAuthz.setClassNm(customAuthzClass.getCustomAuthZClassName());
				customAuthz.setClassDesc(customAuthzClass.getCustomAuthZClassDesc());
				newRuleData.setCustAuthZClassNm(customAuthzClass.getCustomAuthZClassName());
				newRuleData.setCustAuthzExist(rule.isCustomAuthZExists());
				newRuleData.setCustAuthZDocId(rule.getCustAuthZDocId().longValue());
				custAuthzList.add(customAuthz);
				newRuleData.setCustAuthzList(custAuthzList);
			}
			if (rule.getExtendedRule().size() > 0) {
				List<ExtendedRuleData> extendedRuleList = new ArrayList();
				newRuleData.setExtdRuleExist(true);
				for (ExtendedRule extRule : rule.getExtendedRule()) {
					ExtendedRuleData extendedRuleData = new ExtendedRuleData();
					extendedRuleData.setAppId(Long.toString(extRule.getApplicationId()));
					extendedRuleData.setDocId(extRule.getExtRuleDocId());
					extendedRuleData.setExtRuleKey(extRule.getExtendedRuleKey());
					extendedRuleData.setExtRuleOperator(extRule.getExtendedRuleOperator());
					extendedRuleData.setExtRuleType(extRule.getExtendedRuleValueType());
					extendedRuleData.setExtRuleValue(extRule.getExtendedRuleValue());
					extendedRuleList.add(extendedRuleData);
				}
				newRuleData.setExtendedRuleList(extendedRuleList);
			}
			response.add(newRuleData);
		}
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR RULES = " + response.size()));
		return response;
	}

	public static List<RuleData> retrieveForApplication(String appId, boolean mapObjects) throws EscDaoException {
		List<SecurityDataBaseClass> baseList = cdsClient.indexQuery("/rule/@ApplicationId", CdsClient.QUERY_COMPARE.equals, appId, "authZ", CdsSecurityBase.STANZAS.rule, "authZ", CdsSecurityBase.STANZAS.rule, mapObjects);
		return castList(baseList);
	}

	private static List<RuleData> castList(List<SecurityDataBaseClass> tempList) {
		List<RuleData> list = new ArrayList(tempList.size());
		for (SecurityDataBaseClass base : tempList) {
			list.add((RuleData)base);
		}
		return list;
	}

	public static List<RuleData> RetrieveRaw(String appId, Bookmark bookmarkId) {
		logger.info(new FedExLogEntry("Retrieve Raw Rules for appId " + appId));
		if (cdsClient == null) {
			logger.warn(new FedExLogEntry("cdsClient is null! "));
		}
		String bookmark = "";
		List<RuleData> response = new ArrayList();
		int totalDocCount = 0;
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		if (bookmarkId == null) {
			bookmarkId = new Bookmark();
			bookmarkId.setBookmark("5120135");
		}
		StanzaIdType stanzaId = of.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("rule");
		StanzaIdType indexStanzaId = of.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("rule");
		Unmarshaller unmarshaller;
		do {
			IndexQueryResponse indexResponse = cdsClient.indexQuery(BuildIndexQuery(Integer.parseInt(appId), EMPTY_VALUE.longValue(), EMPTY_VALUE.longValue()), stanzaId, indexStanzaId, bookmark);
			List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
			JAXBContext propertiesStanzaContext = null;
			unmarshaller = null;
			try {
				propertiesStanzaContext = JAXBContext.newInstance(com.fedex.enterprise.security.cds.authZ.Rule.class);
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRule RetrieveRaw new instance"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			try {
				unmarshaller = propertiesStanzaContext.createUnmarshaller();
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRule RetrieveRaw create unmarshaller"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
				for (Iterator i$ = queryItem.getKeyedStanzas().iterator(); i$.hasNext(); ) {
					KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
					totalDocCount++;
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						com.fedex.enterprise.security.cds.authZ.Rule currentRule = null;
						try {
							currentRule = (com.fedex.enterprise.security.cds.authZ.Rule)unmarshaller.unmarshal(docElement);
							RuleData newRuleData = new RuleData();
							newRuleData.setActionDocId(currentRule.getActionDocId());
							newRuleData.setAppId(appId);
							newRuleData.setCustAuthZDocId(currentRule.getCustAuthZDocId());
							newRuleData.setDocId(keyedStanzas.getKey());
							if (currentRule.getGrantDenyFlg() == com.fedex.enterprise.security.cds.authZ.GrantDenyFlg.Y) {
								newRuleData.setGrantFlg('Y');
							}
							else {
								newRuleData.setGrantFlg('N');
							}
							newRuleData.setResDocId(currentRule.getResourceDocId());
							newRuleData.setRoleDocId(currentRule.getRoleDocId());
							response.add(newRuleData);
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRule RetrieveRaw unmarshal"), e);
						}
						continue;
					}
				}
				bookmark = queryItem.getPaging().getBookmark();
			}
		}
		while ((!"".equals(bookmark)) && (bookmarkId.getBookmark() == "5120135"));
		bookmarkId.setBookmark(bookmark);
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR RULES = " + totalDocCount));
		return response;
	}

	public static RuleData Retrieve(long docId) {
		return Retrieve(docId, true);
	}

	public static RuleData Retrieve(long docId, boolean loadExtRules) {
		Unmarshaller unmarshaller = null;
		JAXBContext extRefStanzaContext = null;
		RuleData ruleData = null;
		try {
			extRefStanzaContext = JAXBContext.newInstance(com.fedex.enterprise.security.cds.authZ.Rule.class);
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRule Retrieve RuleData new instance"), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		try {
			unmarshaller = extRefStanzaContext.createUnmarshaller();
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRule Retrieve RuleData unmarshaller"), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		try {
			List<Long> keys = new ArrayList();
			keys.add(Long.valueOf(docId));
			KeyQueryRequest request = buildKeyQueryRequest(keys, "rule");
			KeyQueryResponse response = cdsClient.keyQuery(request);
			for (Iterator i$ = response.getKeyedStanzas().iterator(); i$.hasNext(); ) {
				KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
				List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
				for (KeyedStanzasType.Stanza s : stanzaList) {
					Element docElement = s.getAny();
					com.fedex.enterprise.security.cds.authZ.Rule currentRule = null;
					try {
						currentRule = (com.fedex.enterprise.security.cds.authZ.Rule)unmarshaller.unmarshal(docElement);
						ruleData = new RuleData();
						ruleData.setActionDocId(currentRule.getActionDocId());
						ruleData.setAppId(Long.toString(currentRule.getApplicationId()));
						ruleData.setCustAuthZDocId(currentRule.getCustAuthZDocId());
						ruleData.setDocId(keyedStanzas.getKey());
						if (currentRule.getGrantDenyFlg() == com.fedex.enterprise.security.cds.authZ.GrantDenyFlg.Y) {
							ruleData.setGrantFlg('Y');
						}
						else {
							ruleData.setGrantFlg('N');
						}
						ruleData.setResDocId(currentRule.getResourceDocId());
						ruleData.setRoleDocId(currentRule.getRoleDocId());
						if (loadExtRules) {
							List<ExtendedRuleXrefData> extRuleXRefList = CdsSecurityExtRuleXRef.Retrieve(Long.toString(currentRule.getApplicationId()), null);
							List<Long> newKeys = new ArrayList();
							if (extRuleXRefList != null) {
								for (ExtendedRuleXrefData c : extRuleXRefList) {
									newKeys.add(Long.valueOf(c.getExtRuleDocId()));
								}
								ruleData.setExtendedRuleList(CdsSecurityExtendedRule.Retrieve(newKeys));
							}
						}
						if (currentRule.getCustAuthZDocId() != 0L) {
							List<CustomAuthzData> custAuthzList = new ArrayList();
							CustomAuthzData customAuthz = CdsSecurityCustomAuthorizer.getCustomAuthzByKey(Long.valueOf(currentRule.getCustAuthZDocId()));
							custAuthzList.add(customAuthz);
							ruleData.setCustAuthzList(custAuthzList);
							ruleData.setCustAuthZClassNm(customAuthz.getClassNm());
						}
					}
					catch (JAXBException e) {
						logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRule Retrieve RuleData  unmarshal"), e);
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
		return ruleData;
	}

	public static List<RuleData> RetrieveByResourceDocId(long docId, Bookmark bookmarkId) {
		String bookmark = "";
		List<RuleData> response = new ArrayList();
		int totalDocCount = 0;
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		if (bookmarkId == null) {
			bookmarkId = new Bookmark();
			bookmarkId.setBookmark("5120135");
		}
		StanzaIdType stanzaId = of.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("rule");
		StanzaIdType indexStanzaId = of.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("rule");
		Unmarshaller unmarshaller;
		do {
			IndexQueryResponse indexResponse = cdsClient.indexQuery(BuildIndexQuery(EMPTY_VALUE.longValue(), EMPTY_VALUE.longValue(), docId), stanzaId, indexStanzaId, bookmark);
			List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
			JAXBContext propertiesStanzaContext = null;
			unmarshaller = null;
			try {
				propertiesStanzaContext = JAXBContext.newInstance(com.fedex.enterprise.security.cds.authZ.Rule.class);
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRule RetrieveByResourceDocId new instance"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			try {
				unmarshaller = propertiesStanzaContext.createUnmarshaller();
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRule RetrieveByResourceDocId create unmarshaller"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
				for (Iterator i$ = queryItem.getKeyedStanzas().iterator(); i$.hasNext(); ) {
					KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
					totalDocCount++;
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						com.fedex.enterprise.security.cds.authZ.Rule currentRule = null;
						try {
							currentRule = (com.fedex.enterprise.security.cds.authZ.Rule)unmarshaller.unmarshal(docElement);
							RuleData newRuleData = new RuleData();
							newRuleData.setActionDocId(currentRule.getActionDocId());
							newRuleData.setAppId(Long.toString(currentRule.getApplicationId()));
							newRuleData.setCustAuthZDocId(currentRule.getCustAuthZDocId());
							newRuleData.setDocId(keyedStanzas.getKey());
							if (currentRule.getGrantDenyFlg() == com.fedex.enterprise.security.cds.authZ.GrantDenyFlg.Y) {
								newRuleData.setGrantFlg('Y');
							}
							else {
								newRuleData.setGrantFlg('N');
							}
							newRuleData.setResDocId(currentRule.getResourceDocId());
							newRuleData.setRoleDocId(currentRule.getRoleDocId());
							List<ExtendedRuleXrefData> extRuleXRefList = CdsSecurityExtRuleXRef.Retrieve(Long.toString(currentRule.getApplicationId()), null);
							List<Long> keys = new ArrayList();
							if (extRuleXRefList != null) {
								for (ExtendedRuleXrefData c : extRuleXRefList) {
									keys.add(Long.valueOf(c.getExtRuleDocId()));
								}
								newRuleData.setExtendedRuleList(CdsSecurityExtendedRule.Retrieve(keys));
							}
							response.add(newRuleData);
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRule RetrieveByResourceDocId unmarshal"), e);
						}
						continue;
					}
				}
				bookmark = queryItem.getPaging().getBookmark();
			}
		}
		while ((!"".equals(bookmark)) && (bookmarkId.getBookmark() == "5120135"));
		bookmarkId.setBookmark(bookmark);
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR RULES BY RESOURCE = " + totalDocCount));
		return response;
	}

	public static List<RuleData> RetrieveByRoleDocId(long roleDocId, Bookmark bookmarkId) {
		String bookmark = "";
		List<RuleData> response = new ArrayList();
		int totalDocCount = 0;
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		if (bookmarkId == null) {
			bookmarkId = new Bookmark();
			bookmarkId.setBookmark("5120135");
		}
		StanzaIdType stanzaId = of.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("rule");
		StanzaIdType indexStanzaId = of.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("rule");
		Unmarshaller unmarshaller;
		do {
			IndexQueryResponse indexResponse = cdsClient.indexQuery(BuildIndexQuery(EMPTY_VALUE.longValue(), roleDocId, EMPTY_VALUE.longValue()), stanzaId, indexStanzaId, bookmark);
			List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
			JAXBContext propertiesStanzaContext = null;
			unmarshaller = null;
			try {
				propertiesStanzaContext = JAXBContext.newInstance(com.fedex.enterprise.security.cds.authZ.Rule.class);
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRule RetrieveByRoleDocId new instance"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			try {
				unmarshaller = propertiesStanzaContext.createUnmarshaller();
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRule RetrieveByRoleDocId create unmarshaller"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
				for (Iterator i$ = queryItem.getKeyedStanzas().iterator(); i$.hasNext(); ) {
					KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
					totalDocCount++;
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						com.fedex.enterprise.security.cds.authZ.Rule currentRule = null;
						try {
							currentRule = (com.fedex.enterprise.security.cds.authZ.Rule)unmarshaller.unmarshal(docElement);
							RuleData newRuleData = new RuleData();
							newRuleData.setActionDocId(currentRule.getActionDocId());
							newRuleData.setAppId(Long.toString(currentRule.getApplicationId()));
							newRuleData.setCustAuthZDocId(currentRule.getCustAuthZDocId());
							newRuleData.setDocId(keyedStanzas.getKey());
							if (currentRule.getGrantDenyFlg() == com.fedex.enterprise.security.cds.authZ.GrantDenyFlg.Y) {
								newRuleData.setGrantFlg('Y');
							}
							else {
								newRuleData.setGrantFlg('N');
							}
							newRuleData.setResDocId(currentRule.getResourceDocId());
							newRuleData.setRoleDocId(currentRule.getRoleDocId());
							List<ExtendedRuleXrefData> extRuleXRefList = CdsSecurityExtRuleXRef.Retrieve(Long.toString(currentRule.getApplicationId()), null);
							List<Long> keys = new ArrayList();
							for (ExtendedRuleXrefData c : extRuleXRefList) {
								keys.add(Long.valueOf(c.getExtRuleDocId()));
							}
							newRuleData.setExtendedRuleList(CdsSecurityExtendedRule.Retrieve(keys));
							response.add(newRuleData);
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRule RetrieveByRoleDocId unmarshal"), e);
						}
						continue;
					}
				}
				bookmark = queryItem.getPaging().getBookmark();
			}
		}
		while ((!"".equals(bookmark)) && (bookmarkId.getBookmark() == "5120135"));
		bookmarkId.setBookmark(bookmark);
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR RULES BY ROLE = " + totalDocCount));
		return response;
	}

	public static long retrieveByAllKeys(String applicationId, String roleName, String actionName, String resourceName, char grantDenyFlg) {
		Long appId = Long.valueOf(applicationId);
		com.fedex.framework.cds.ObjectFactory objectFactory = new com.fedex.framework.cds.ObjectFactory();
		long ruleDocId = 0L;
		StanzaIdType stanzaId = objectFactory.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("rule");
		StanzaIdType indexStanzaId = objectFactory.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("rule");
		Long actionDocId = Long.valueOf(EscUtils.getActionDocIdbyName(actionName, applicationId));
		Long roleDocId = Long.valueOf(EscUtils.getRoleDocIdbyName(roleName, applicationId));
		String resName = "";
		if ((!resourceName.endsWith("/")) && (!resourceName.endsWith("*"))) {
			resName = resourceName + "/";
		}
		else {
			resName = resourceName;
		}
		Long resourceDocId = Long.valueOf(EscUtils.getResourceDocIdbyName(resName, applicationId));
		try {
			IndexQueryResponse response = cdsClient.indexQuery(BuildRuleIndexQuery(appId.longValue(), roleDocId.longValue(), actionDocId.longValue(), resourceDocId.longValue(), grantDenyFlg), stanzaId, indexStanzaId, null);
			List<IndexQueryResponse.QueryItem> queryItemList = response.getQueryItem();
			for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
				for (KeyedStanzasType keyedStanza : queryItem.getKeyedStanzas()) {
					ruleDocId = keyedStanza.getKey();
				}
			}
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Caught exception e: " + e.toString()));
			throw new RuntimeException(e);
		}
		return ruleDocId;
	}

	public static RuleData retrieveRuleByAllKeys(String applicationId, String roleName, String actionName, String resourceName, char grantDenyFlg) {
		RuleData newRuleData = new RuleData();
		Long appId = Long.valueOf(applicationId);
		com.fedex.framework.cds.ObjectFactory objectFactory = new com.fedex.framework.cds.ObjectFactory();
		StanzaIdType stanzaId = objectFactory.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("rule");
		StanzaIdType indexStanzaId = objectFactory.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("rule");
		Long actionDocId = Long.valueOf(EscUtils.getActionDocIdbyName(actionName, applicationId));
		Long roleDocId = Long.valueOf(EscUtils.getRoleDocIdbyName(roleName, applicationId));
		String resName = "";
		if ((!resourceName.endsWith("/")) && (!resourceName.endsWith("*"))) {
			resName = resourceName + "/";
		}
		Long resourceDocId = Long.valueOf(EscUtils.getResourceDocIdbyName(resName, applicationId));
		try {
			IndexQueryResponse response = cdsClient.indexQuery(BuildRuleIndexQuery(appId.longValue(), roleDocId.longValue(), actionDocId.longValue(), resourceDocId.longValue(), grantDenyFlg), stanzaId, indexStanzaId, null);
			List<IndexQueryResponse.QueryItem> queryItemList = response.getQueryItem();
			JAXBContext ruleStanzaContext = null;
			Unmarshaller unmarshaller = null;
			try {
				ruleStanzaContext = JAXBContext.newInstance(com.fedex.enterprise.security.cds.authZ.Rule.class);
				unmarshaller = ruleStanzaContext.createUnmarshaller();
			}
			catch (JAXBException e) {
				logger.error(new FedExLogEntry(" The failed to retrieve the ruleData from CDS : " + e.getMessage()));
				throw e;
			}
			for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
				for (Iterator i$ = queryItem.getKeyedStanzas().iterator(); i$.hasNext(); ) {
					KeyedStanzasType keyedStanza = (KeyedStanzasType)i$.next();
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanza.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						com.fedex.enterprise.security.cds.authZ.Rule rule = null;
						try {
							rule = (com.fedex.enterprise.security.cds.authZ.Rule)unmarshaller.unmarshal(docElement);
							newRuleData.setDocId(keyedStanza.getKey());
							newRuleData.setActionDocId(rule.getActionDocId());
							newRuleData.setAppId(Long.toString(rule.getApplicationId()));
							newRuleData.setCustAuthZDocId(rule.getCustAuthZDocId());
							if (rule.getGrantDenyFlg() == com.fedex.enterprise.security.cds.authZ.GrantDenyFlg.Y) {
								newRuleData.setGrantFlg('Y');
							}
							else {
								newRuleData.setGrantFlg('N');
							}
							newRuleData.setResDocId(rule.getResourceDocId());
							newRuleData.setRoleDocId(rule.getRoleDocId());
							List<ExtendedRuleXrefData> extRuleXRefList = CdsSecurityExtRuleXRef.Retrieve(keyedStanza.getKey(), null);
							List<Long> keys = new ArrayList();
							for (ExtendedRuleXrefData c : extRuleXRefList) {
								keys.add(Long.valueOf(c.getExtRuleDocId()));
							}
							newRuleData.setExtendedRuleList(CdsSecurityExtendedRule.Retrieve(keys));
						}
						catch (JAXBException e) {
							logger.warn(new FedExLogEntry("The Security API was unable to unmarshall the document: " + e.getMessage()));
						}
						continue;
					}
				}
			}
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Caught exception e: " + e.toString()));
			throw new RuntimeException(e);
		}
		return newRuleData;
	}

	private static List<IndexElementType> BuildIndexQuery(long appID, long roleDocId, long resourceDocId) {
		List<IndexElementType> indexElements = new ArrayList();
		if (appID != EMPTY_VALUE.longValue()) {
			IndexElementType appId = new IndexElementType();
			appId.setXpath("/rule/@ApplicationId");
			appId.setComparison("equals");
			appId.setValue(Long.toString(appID));
			indexElements.add(appId);
		}
		if (roleDocId != EMPTY_VALUE.longValue()) {
			IndexElementType appId = new IndexElementType();
			appId.setXpath("/rule/@RoleDocId");
			appId.setComparison("equals");
			appId.setValue(Long.toString(roleDocId));
			indexElements.add(appId);
		}
		if (resourceDocId != EMPTY_VALUE.longValue()) {
			IndexElementType appId = new IndexElementType();
			appId.setXpath("/rule/@ResourceDocId");
			appId.setComparison("equals");
			appId.setValue(Long.toString(resourceDocId));
			indexElements.add(appId);
		}
		return indexElements;
	}

	public static List<IndexElementType> BuildRuleIndexQuery(long applicationId, long roleDocId, long actionDocId, long resourceDocId, char grantFlg) {
		List<IndexElementType> indexElements = new ArrayList();
		if (applicationId != EMPTY_VALUE.longValue()) {
			IndexElementType appId = new IndexElementType();
			appId.setXpath("/rule/@ApplicationId");
			appId.setComparison("equals");
			appId.setValue(Long.toString(applicationId));
			indexElements.add(appId);
		}
		if (actionDocId != EMPTY_VALUE.longValue()) {
			IndexElementType appId = new IndexElementType();
			appId.setXpath("/rule/@ActionDocId");
			appId.setComparison("equals");
			appId.setValue(Long.toString(actionDocId));
			indexElements.add(appId);
		}
		if (roleDocId != EMPTY_VALUE.longValue()) {
			IndexElementType appId = new IndexElementType();
			appId.setXpath("/rule/@RoleDocId");
			appId.setComparison("equals");
			appId.setValue(Long.toString(roleDocId));
			indexElements.add(appId);
		}
		if (resourceDocId != EMPTY_VALUE.longValue()) {
			IndexElementType appId = new IndexElementType();
			appId.setXpath("/rule/@ResourceDocId");
			appId.setComparison("equals");
			appId.setValue(Long.toString(resourceDocId));
			indexElements.add(appId);
		}
		if (grantFlg != ' ') {
			IndexElementType appId = new IndexElementType();
			appId.setXpath("/rule/@GrantDenyFlg");
			appId.setComparison("equals");
			appId.setValue(Character.toString(grantFlg));
			indexElements.add(appId);
		}
		return indexElements;
	}

	public static List<RuleData> RetrieveByResourceDocIdHflow(long docId, Bookmark bookmarkId) {
		String bookmark = "";
		List<RuleData> response = new ArrayList();
		int totalDocCount = 0;
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		if (bookmarkId == null) {
			bookmarkId = new Bookmark();
			bookmarkId.setBookmark("5120135");
		}
		StanzaIdType stanzaId = of.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("rule");
		StanzaIdType indexStanzaId = of.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("rule");
		Unmarshaller unmarshaller;
		do {
			IndexQueryResponse indexResponse = cdsClient.indexQuery(BuildIndexQuery(EMPTY_VALUE.longValue(), EMPTY_VALUE.longValue(), docId), stanzaId, indexStanzaId, bookmark);
			List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
			JAXBContext propertiesStanzaContext = null;
			unmarshaller = null;
			try {
				propertiesStanzaContext = JAXBContext.newInstance(com.fedex.enterprise.security.cds.authZ.Rule.class);
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRule Retrieve create marshaller"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			try {
				unmarshaller = propertiesStanzaContext.createUnmarshaller();
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRule Retrieve create marshaller"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
				for (Iterator i$ = queryItem.getKeyedStanzas().iterator(); i$.hasNext(); ) {
					KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
					totalDocCount++;
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						com.fedex.enterprise.security.cds.authZ.Rule currentRule = null;
						try {
							currentRule = (com.fedex.enterprise.security.cds.authZ.Rule)unmarshaller.unmarshal(docElement);
							RuleData newRuleData = new RuleData();
							newRuleData.setActionDocId(currentRule.getActionDocId());
							if (currentRule.getActionDocId() != 0L) {
								ActionData actionData = CdsSecurityAction.getActionByKey(Long.valueOf(currentRule.getActionDocId()));
								if (actionData != null) {
									newRuleData.setActionNm(actionData.getActionNm());
								}
							}
							newRuleData.setAppId(Long.toString(currentRule.getApplicationId()));
							newRuleData.setDocId(keyedStanzas.getKey());
							if (currentRule.getGrantDenyFlg() == com.fedex.enterprise.security.cds.authZ.GrantDenyFlg.Y) {
								newRuleData.setGrantFlg('Y');
							}
							else {
								newRuleData.setGrantFlg('N');
							}
							newRuleData.setResDocId(currentRule.getResourceDocId());
							newRuleData.setRoleDocId(currentRule.getRoleDocId());
							response.add(newRuleData);
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRule Retrieve create unmarshal"), e);
						}
						continue;
					}
				}
				bookmark = queryItem.getPaging().getBookmark();
			}
		}
		while ((!"".equals(bookmark)) && (bookmarkId.getBookmark() == "5120135"));
		bookmarkId.setBookmark(bookmark);
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR RULES BY RESOURCE = " + totalDocCount));
		return response;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\cds\CdsSecurityRule.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */