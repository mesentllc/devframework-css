package com.fedex.cds;

import com.fedex.cds.plugin.jaxb.ResourceList;
import com.fedex.common.icefaces.util.FacesUtils;
import com.fedex.ea.framework.securityapi.dao.esc.EscDaoException;
import com.fedex.enterprise.security.esc.view.model.WssoHandler;
import com.fedex.enterprise.security.resource.ResourceData;
import com.fedex.enterprise.security.resource.ResourceService;
import com.fedex.enterprise.security.rule.ExtendedRuleXrefData;
import com.fedex.enterprise.security.rule.RuleData;
import com.fedex.enterprise.security.utils.EscUtils;
import com.fedex.enterprise.security.utils.SecurityDataBaseClass;
import com.fedex.framework.cds.EnrichedQueryRequest;
import com.fedex.framework.cds.EnrichedQueryResponse;
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
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.ws.soap.SOAPFaultException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class CdsSecurityResource
		extends CdsSecurityBase
		implements ResourceService {
	private static final String THE_ESC = "the ESC.";
	private static final String FROM = " from ";
	private static final String APP = "App #";
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(CdsSecurityResource.class);

	private enum QUERY_TYPE {
		APPID,
		NAME,
		PARTIALNAME,
		ROOT;

		QUERY_TYPE() {
		}
	}

	private final String ROOTFLAG = "Y";

	public void deleteResourceByRoot(String appId, String root) {
		deleteResourceByRoot(appId, root, false);
	}

	public void deleteResourceByRoot(String appId, String root, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		if ((!systemOverride) && (FacesContext.getCurrentInstance() != null)) {
			WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
			onBehalfOf = roleHandler.getUserId();
		}
		deleteResourceByRoot(appId, root, false, onBehalfOf);
	}

	public void deleteResourceByRoot(String appId, String root, boolean systemOverride, String onBehalfOf) {
		String callingApp = "4112";
		List<Long> keys = new ArrayList();
		List<InsertRequest.InsertItem> records = new ArrayList();
		List<ResourceData> objectList = ProcessQuery(QUERY_TYPE.PARTIALNAME, appId, root, null);
		logger.info(new FedExLogEntry("About to delete " + objectList.size() + " subresources..."));
		List<InsertRequest.InsertItem> auditRecordsForRules = new ArrayList();
		List<InsertRequest.InsertItem> auditRecords = new ArrayList();
		List<Long> ruleKeys = new ArrayList();
		List<Long> extRuleXrefKeys = new ArrayList();
		for (ResourceData resourceData : objectList) {
			List<RuleData> rules = CdsSecurityRule.RetrieveByResourceDocId(resourceData.getDocId(), new Bookmark());
			try {
				if ((rules != null) && (!rules.isEmpty())) {
					for (Iterator i$ = rules.iterator(); i$.hasNext(); ) {
						RuleData rule = (RuleData)i$.next();
						ruleKeys.add(Long.valueOf(rule.getDocId()));
						String desc = "Rule ' " + EscUtils.getRuleNameByDocId(rule.getDocId(), appId) + "' was removed by the ESC due to the deletion of resource " + resourceData.getResName() + ".";
						InsertRequest.InsertItem auditItem = createAuditRecord(resourceData.getAppId(), onBehalfOf, desc, "delete", "rule");
						auditRecordsForRules.add(auditItem);
						List<ExtendedRuleXrefData> extRuleXRef = CdsSecurityExtRuleXRef.Retrieve(rule.getDocId(), new Bookmark());
						for (ExtendedRuleXrefData xref : extRuleXRef) {
							String desc2 = "Extended Rule #" + xref.getDocId() + " was removed from Rule # " + rule.getDocId() + " by the ESC due to the deletion of resource " + resourceData.getResName() + ".";
							InsertRequest.InsertItem item = createAuditRecord(resourceData.getAppId(), onBehalfOf, desc2, "delete", "extRuleXRef");
							auditRecords.add(item);
							extRuleXrefKeys.add(Long.valueOf(xref.getDocId()));
						}
					}
				}
			}
			catch (Exception e) {
				logger.warn(new FedExLogEntry("WARNING: couldn't find the rules/extrulexrefs for this resource."));
			}
			String desc = resourceData.getResName() + " was deleted by " + onBehalfOf + " from " + ("4112".equals("4112") ? "the ESC." : "App #4112");
			InsertRequest.InsertItem auditRecord = createAuditRecord(resourceData.getAppId(), onBehalfOf, desc, "delete", "resource");
			records.add(auditRecord);
			keys.add(Long.valueOf(resourceData.getDocId()));
		}
		try {
			if ((extRuleXrefKeys != null) && (!extRuleXrefKeys.isEmpty())) {
				CdsSecurityExtRuleXRef.Delete(extRuleXrefKeys, "extRuleXRef", auditRecords);
			}
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("WARNING: unable to properly delete any XRefs for the rules."));
		}
		try {
			if ((ruleKeys != null) && (!ruleKeys.isEmpty())) {
				CdsSecurityRule.Delete(ruleKeys, "rule", auditRecordsForRules);
			}
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("WARNING: unable to properly delete rules for the resource in question."));
		}
		if (!keys.isEmpty()) {
			Delete(keys, "resource", records, systemOverride);
		}
	}

	public List<ResourceData> getResourceRootsForApplication(String appId, Bookmark bookmark) {
		return ProcessQuery(QUERY_TYPE.ROOT, appId, null, bookmark);
	}

	public List<ResourceData> getResourcesForApplication(String appId, Bookmark bookMark) {
		return ProcessQuery(QUERY_TYPE.APPID, appId, null, bookMark);
	}

	public List<ResourceData> getResourcesForApplicationByPartialResource(String appId, String partResName, Bookmark bookmarkId) {
		if ("*".equals(partResName)) {
			return ProcessQuery(QUERY_TYPE.NAME, appId, partResName, bookmarkId);
		}
		return ProcessQuery(QUERY_TYPE.PARTIALNAME, appId, partResName, bookmarkId);
	}

	public List<ResourceData> ProcessQuery(QUERY_TYPE queryType, String appId, String partResName, Bookmark bookmarkId) {
		String bookmark = "";
		String lastBookmark = "";
		boolean bailout = false;
		List<ResourceData> response = new ArrayList();
		int totalDocCount = 0;
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		if (bookmarkId == null) {
			bookmarkId = new Bookmark();
			bookmarkId.setBookmark("5120135");
		}
		StanzaIdType stanzaId = of.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("resource");
		StanzaIdType indexStanzaId = of.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("resource");
		IndexQueryResponse indexResponse = null;
		Unmarshaller unmarshaller;
		do {
			try {
				indexResponse = cdsClient.indexQuery(BuildIndexQuery(queryType, Integer.parseInt(appId), partResName, "Y"), stanzaId, indexStanzaId, bookmark);
			}
			catch (SoapFaultClientException sfx) {
				throw sfx;
			}
			List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
			JAXBContext resourceStanzaContext = null;
			unmarshaller = null;
			try {
				resourceStanzaContext = JAXBContext.newInstance(com.fedex.enterprise.security.cds.authZ.Resource.class);
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityResource ProcessQuery new instance"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			try {
				unmarshaller = resourceStanzaContext.createUnmarshaller();
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityResource ProcessQuery create unmarshaller"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
				for (Iterator i$ = queryItem.getKeyedStanzas().iterator(); i$.hasNext(); ) {
					KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
					totalDocCount++;
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						com.fedex.enterprise.security.cds.authZ.Resource currentResource = null;
						try {
							currentResource = (com.fedex.enterprise.security.cds.authZ.Resource)unmarshaller.unmarshal(docElement);
							ResourceData newResourceData = new ResourceData();
							newResourceData.setResDesc(currentResource.getResourceDesc());
							newResourceData.setResName(currentResource.getResourceName());
							newResourceData.setAppId(appId);
							newResourceData.setDocId(keyedStanzas.getKey());
							newResourceData.setRootFlg(currentResource.getRootFlg().charAt(0));
							response.add(newResourceData);
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityResource ProcessQuery unmarshal"), e);
						}
						continue;
					}
				}
				bookmark = queryItem.getPaging().getBookmark();
				logger.info(new FedExLogEntry("Bookmark = " + bookmark + " (Old Bookmark: " + lastBookmark));
				if (bookmark.equals(lastBookmark)) {
					bailout = true;
					break;
				}
				lastBookmark = bookmark;
			}
		}
		while ((!bailout) &&
		       (!"".equals(bookmark)) && (bookmarkId.getBookmark() == "5120135"));
		bookmarkId.setBookmark(bookmark);
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR RESOURCES = " + totalDocCount));
		return response;
	}

	public long insertResource(ResourceData resourceData) {
		return insertResource(resourceData, false);
	}

	public long insertResource(ResourceData resourceData, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		if ((!systemOverride) && (FacesContext.getCurrentInstance() != null)) {
			WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
			onBehalfOf = roleHandler.getUserId();
		}
		return insertResource(resourceData, systemOverride, onBehalfOf, "");
	}

	public long insertResource(ResourceData resourceData, boolean systemOverride, String onBehalfOf, String appId) {
		logger.info(new FedExLogEntry("Inserting the following Resource: " + resourceData));
		List<Document> request = new ArrayList();
		try {
			com.fedex.enterprise.security.cds.authZ.ObjectFactory securityObjectFactory = new com.fedex.enterprise.security.cds.authZ.ObjectFactory();
			JAXBContext propJaxbContext = JAXBContext.newInstance("com.fedex.enterprise.security.cds.authZ");
			Marshaller propMarshaller = propJaxbContext.createMarshaller();
			com.fedex.enterprise.security.cds.authZ.Resource cdsResource = securityObjectFactory.createResource();
			String description = resourceData.getResDesc();
			if ((description == null) || (description.length() == 0)) {
				description = "NA";
			}
			cdsResource.setResourceDesc(description);
			cdsResource.setResourceName(resourceData.getResName());
			cdsResource.setDomain("authZ");
			cdsResource.setMajorVersion(STANZA_DESC_MAJOR_VER);
			cdsResource.setMinorVersion(STANZA_DESC_MINOR_VER);
			cdsResource.setApplicationId(Long.parseLong(resourceData.getAppId()));
			cdsResource.setRootFlg(String.valueOf(resourceData.getRootFlg()));
			Document doc = BuildDocument();
			propMarshaller.marshal(cdsResource, doc);
			request.add(doc);
			String callingApp = "";
			if (EscUtils.isNullOrBlank(appId)) {
				callingApp = "4112";
			}
			else {
				callingApp = appId;
			}
			String desc = resourceData.getResName() + " was created by " + onBehalfOf + " from " + (callingApp.equals("4112") ? "the ESC." : new StringBuilder().append("App #").append(callingApp).toString());
			InsertRequest.InsertItem auditRecord = createAuditRecord(resourceData.getAppId(), onBehalfOf, desc, "create", "resource");
			List<InsertRequest.InsertItem> auditRecords = new ArrayList();
			auditRecords.add(auditRecord);
			List<Long> keys = cdsClient.insert(request, auditRecords, systemOverride);
			resourceData.setDocId(keys.get(0).longValue());
			logger.info(new FedExLogEntry("Resource Key: " + keys.get(0)));
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
		return resourceData.getDocId();
	}

	public void updateResource(ResourceData resourceData) {
		updateResource(resourceData, false);
	}

	public void updateResource(ResourceData resourceData, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		if ((!systemOverride) && (FacesContext.getCurrentInstance() != null)) {
			WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
			onBehalfOf = roleHandler.getUserId();
		}
		updateResource(resourceData, false, onBehalfOf, "");
	}

	public void updateResource(ResourceData resourceData, boolean systemOverride, String onBehalfOf, String appId) {
		HashMap<String, String> xpathList = new HashMap();
		String description = resourceData.getResDesc();
		if ((description == null) || (description.length() == 0)) {
			description = "NA";
		}
		xpathList.put("/resource/@ResourceName", resourceData.getResName());
		xpathList.put("/resource/@ResourceDesc", description);
		String callingApp = "";
		if (EscUtils.isNullOrBlank(appId)) {
			callingApp = "4112";
		}
		else {
			callingApp = appId;
		}
		String desc = resourceData.getResName() + " was modified by " + onBehalfOf + " from " + (callingApp.equals("4112") ? "the ESC." : new StringBuilder().append("App #").append(callingApp).toString());
		InsertRequest.InsertItem auditRecord = createAuditRecord(resourceData.getAppId(), onBehalfOf, desc, "modify", "resource");
		cdsClient.update(xpathList, resourceData.getDocId(), "authZ", "resource", auditRecord, systemOverride);
	}

	public void deleteResource(ResourceData resourceData) {
		deleteResource(resourceData, false);
	}

	public void deleteResource(ResourceData resourceData, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		if ((!systemOverride) && (FacesContext.getCurrentInstance() != null)) {
			WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
			onBehalfOf = roleHandler.getUserId();
		}
		deleteResource(resourceData, false, onBehalfOf, "");
	}

	public void deleteResource(ResourceData resourceData, boolean systemOverride, String onBehalfOf, String appId) {
		try {
			String callingApp = "";
			if (EscUtils.isNullOrBlank(appId)) {
				callingApp = "4112";
			}
			else {
				callingApp = appId;
			}
			if ((!resourceData.getResName().endsWith("*")) && (resourceData.getResName().length() > 3)) {
				deleteResourceByRoot(resourceData.getAppId(), resourceData.getResName(), systemOverride);
			}
			else {
				List<RuleData> rules = CdsSecurityRule.RetrieveByResourceDocId(resourceData.getDocId(), new Bookmark());
				List<InsertRequest.InsertItem> auditRecordsForRules = new ArrayList();
				List<InsertRequest.InsertItem> auditRecords = new ArrayList();
				List<Long> ruleKeys = new ArrayList();
				List<Long> extRuleXrefKeys = new ArrayList();
				try {
					if ((rules != null) && (!rules.isEmpty())) {
						for (Iterator i$ = rules.iterator(); i$.hasNext(); ) {
							RuleData rule = (RuleData)i$.next();
							ruleKeys.add(Long.valueOf(rule.getDocId()));
							String desc = "Rule ' " + EscUtils.getRuleNameByDocId(rule.getDocId(), appId) + "' was removed by the ESC due to the deletion of resource " + resourceData.getResName() + ".";
							InsertRequest.InsertItem auditItem = createAuditRecord(resourceData.getAppId(), onBehalfOf, desc, "delete", "rule");
							auditRecordsForRules.add(auditItem);
							List<ExtendedRuleXrefData> extRuleXRef = CdsSecurityExtRuleXRef.Retrieve(rule.getDocId(), new Bookmark());
							for (ExtendedRuleXrefData xref : extRuleXRef) {
								String desc2 = "Extended Rule #" + xref.getDocId() + " was removed from Rule # " + rule.getDocId() + " by the ESC due to the deletion of resource " + resourceData.getResName() + ".";
								InsertRequest.InsertItem item = createAuditRecord(resourceData.getAppId(), onBehalfOf, desc2, "delete", "extRuleXRef");
								auditRecords.add(item);
								extRuleXrefKeys.add(Long.valueOf(xref.getDocId()));
							}
						}
					}
				}
				catch (Exception e) {
					logger.warn(new FedExLogEntry("WARNING: couldn't find the rules/extrulexrefs for this resource."));
				}
				try {
					if ((extRuleXrefKeys != null) && (!extRuleXrefKeys.isEmpty())) {
						CdsSecurityExtRuleXRef.Delete(extRuleXrefKeys, "extRuleXRef", auditRecords);
					}
				}
				catch (Exception e) {
					logger.warn(new FedExLogEntry("WARNING: unable to properly delete any XRefs for the rules."));
				}
				try {
					if ((ruleKeys != null) && (!ruleKeys.isEmpty())) {
						CdsSecurityRule.Delete(ruleKeys, "rule", auditRecordsForRules);
					}
				}
				catch (Exception e) {
					logger.warn(new FedExLogEntry("WARNING: unable to properly delete rules for the resource in question."));
				}
				String desc = resourceData.getResName() + " was deleted by " + onBehalfOf + " from " + (callingApp.equals("4112") ? "the ESC." : new StringBuilder().append("App #").append(callingApp).toString());
				InsertRequest.InsertItem auditRecord = createAuditRecord(resourceData.getAppId(), onBehalfOf, desc, "delete", "resource");
				Delete(Long.valueOf(resourceData.getDocId()), "resource", auditRecord, systemOverride);
			}
		}
		catch (SOAPFaultException sfe) {
			throw new RuntimeException(sfe.getMessage(), sfe);
		}
		catch (SecurityException se) {
			throw new RuntimeException(se.getMessage(), se);
		}
	}

	private static List<IndexElementType> BuildIndexQuery(QUERY_TYPE queryType, int appID, String partialResourceName, String rootFlag) {
		List<IndexElementType> indexElements = new ArrayList();
		IndexElementType appId = new IndexElementType();
		appId.setXpath("/resource/@ApplicationId");
		appId.setComparison("equals");
		appId.setValue(Integer.toString(appID));
		indexElements.add(appId);
		switch (queryType) {
			case NAME:
				if (null != partialResourceName) {
					IndexElementType resourceName = new IndexElementType();
					resourceName.setXpath("/resource/@ResourceName");
					resourceName.setComparison("equals");
					resourceName.setValue(partialResourceName);
					indexElements.add(resourceName);
				}
				break;
			case PARTIALNAME:
				if (null != partialResourceName) {
					IndexElementType resourceName = new IndexElementType();
					resourceName.setXpath("/resource/@ResourceName");
					resourceName.setComparison("like");
					resourceName.setValue(partialResourceName + "%");
					indexElements.add(resourceName);
				}
				break;
			case ROOT:
				if (null != rootFlag) {
					IndexElementType rootFlagValue = new IndexElementType();
					rootFlagValue.setXpath("/resource/@RootFlg");
					rootFlagValue.setComparison("equals");
					rootFlagValue.setValue(rootFlag);
					indexElements.add(rootFlagValue);
				}
				break;
		}
		return indexElements;
	}

	public static ResourceData getResourceByKey(Long docId) {
		Unmarshaller unmarshaller = null;
		JAXBContext resourceStanzaContext = null;
		try {
			resourceStanzaContext = JAXBContext.newInstance(com.fedex.enterprise.security.cds.authZ.Resource.class);
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityResource getResourceByKey new instance"), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		try {
			unmarshaller = resourceStanzaContext.createUnmarshaller();
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityResource getResourceByKey create unmarshaller"), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		ResourceData resourceData = new ResourceData();
		List<Long> keyList = new ArrayList();
		keyList.add(docId);
		KeyQueryRequest request = buildKeyQueryRequest(keyList, "resource");
		KeyQueryResponse response = cdsClient.keyQuery(request);
		for (Iterator i$ = response.getKeyedStanzas().iterator(); i$.hasNext(); ) {
			KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
			List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
			for (KeyedStanzasType.Stanza s : stanzaList) {
				Element docElement = s.getAny();
				com.fedex.enterprise.security.cds.authZ.Resource r = null;
				try {
					r = (com.fedex.enterprise.security.cds.authZ.Resource)unmarshaller.unmarshal(docElement);
					resourceData.setAppId(String.valueOf(r.getApplicationId()));
					resourceData.setDocId(keyedStanzas.getKey());
					resourceData.setResDesc(r.getResourceDesc());
					resourceData.setResName(r.getResourceName());
					resourceData.setRootFlg(r.getRootFlg().charAt(0));
				}
				catch (JAXBException e) {
					logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityResource getResourceByKey unmarshal"), e);
				}
				continue;
			}
		}
		return resourceData;
	}

	public static Map<Long, String> retrieveNames(List<Long> keys) throws EscDaoException {
		HashMap<Long, String> retList = new HashMap();
		List<ResourceData> resourceDataList = retrieve(keys, true);
		for (ResourceData resourceData : resourceDataList) {
			retList.put(Long.valueOf(resourceData.getDocId()), resourceData.getResName());
		}
		return retList;
	}

	public static List<ResourceData> retrieve(List<Long> keys, boolean mapObjects) throws EscDaoException {
		return castList(cdsClient.keyQuery(keys, "authZ", CdsSecurityBase.STANZAS.resource, mapObjects));
	}

	private static List<ResourceData> castList(List<SecurityDataBaseClass> tempList) {
		List<ResourceData> list = new ArrayList(tempList.size());
		for (SecurityDataBaseClass base : tempList) {
			list.add((ResourceData)base);
		}
		return list;
	}

	public static Map<Long, String> getResourceNamesByKeys(List<Long> docIds) {
		if ((docIds == null) || (docIds.isEmpty())) {
			return Collections.emptyMap();
		}
		Unmarshaller unmarshaller = null;
		JAXBContext resourceStanzaContext = null;
		try {
			resourceStanzaContext = JAXBContext.newInstance(com.fedex.enterprise.security.cds.authZ.Resource.class);
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityResource getResourceNamesByKeys new instance"), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		try {
			unmarshaller = resourceStanzaContext.createUnmarshaller();
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityResource getResourceNamesByKeys create unmarshaller"), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		HashMap<Long, String> resourceList = new HashMap();
		Iterator<Long> it = docIds.iterator();
		Iterator i$;
		KeyedStanzasType keyedStanzas;
		do {
			List<Long> listOfKeys = new ArrayList();
			for (int counter = 0; counter < 500; counter++) {
				if (it.hasNext()) {
					listOfKeys.add(it.next());
				}
			}
			KeyQueryRequest request = buildKeyQueryRequest(listOfKeys, "resource");
			KeyQueryResponse response = cdsClient.keyQuery(request);
			for (i$ = response.getKeyedStanzas().iterator(); i$.hasNext(); ) {
				keyedStanzas = (KeyedStanzasType)i$.next();
				List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
				for (KeyedStanzasType.Stanza s : stanzaList) {
					Element docElement = s.getAny();
					com.fedex.enterprise.security.cds.authZ.Resource r = null;
					try {
						r = (com.fedex.enterprise.security.cds.authZ.Resource)unmarshaller.unmarshal(docElement);
						resourceList.put(Long.valueOf(keyedStanzas.getKey()), r.getResourceName());
					}
					catch (JAXBException e) {
						logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityResource getResourceNamesByKeys unmarshal"), e);
					}
					continue;
				}
			}
		}
		while (it.hasNext());
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR RESOURCE NAMES = " + resourceList.size()));
		return resourceList;
	}

	public ResourceData getResource(long docId) {
		return null;
	}

	public ResourceData getResourceByName(String appId, String resourceName) {
		List<ResourceData> resources = ProcessQuery(QUERY_TYPE.NAME, appId, resourceName, new Bookmark());
		if ((resources != null) && (!resources.isEmpty())) {
			return resources.get(0);
		}
		return null;
	}

	public static List<Long> insertResource(String appId, String applicationName, boolean systemOverride, String onBehalfOf) {
		logger.info(new FedExLogEntry("Inserting the following Resource: " + appId));
		List<Document> request = new ArrayList();
		List<Long> keys;
		try {
			com.fedex.enterprise.security.cds.authZ.ObjectFactory securityObjectFactory = new com.fedex.enterprise.security.cds.authZ.ObjectFactory();
			JAXBContext propJaxbContext = JAXBContext.newInstance("com.fedex.enterprise.security.cds.authZ");
			Marshaller propMarshaller = propJaxbContext.createMarshaller();
			com.fedex.enterprise.security.cds.authZ.Resource rootResource = securityObjectFactory.createResource();
			rootResource.setResourceDesc(appId + " " + applicationName + "  root resource");
			rootResource.setResourceName(appId);
			rootResource.setDomain("authZ");
			rootResource.setMajorVersion(STANZA_DESC_MAJOR_VER);
			rootResource.setMinorVersion(STANZA_DESC_MINOR_VER);
			rootResource.setApplicationId(Long.parseLong("4112"));
			rootResource.setRootFlg("Y");
			Document rootResourceDoc = BuildDocument();
			propMarshaller.marshal(rootResource, rootResourceDoc);
			request.add(rootResourceDoc);
			com.fedex.enterprise.security.cds.authZ.Resource starResource = securityObjectFactory.createResource();
			starResource.setResourceDesc(appId + " " + applicationName + " anything resource");
			starResource.setResourceName(appId + "*");
			starResource.setDomain("authZ");
			starResource.setMajorVersion(STANZA_DESC_MAJOR_VER);
			starResource.setMinorVersion(STANZA_DESC_MINOR_VER);
			starResource.setApplicationId(Long.parseLong("4112"));
			starResource.setRootFlg("N");
			Document starResourceDoc = BuildDocument();
			propMarshaller.marshal(starResource, starResourceDoc);
			request.add(starResourceDoc);
			com.fedex.enterprise.security.cds.authZ.Resource actionResource = securityObjectFactory.createResource();
			actionResource.setResourceDesc(appId + " " + applicationName + " action resource");
			actionResource.setResourceName(appId + "ACTION/");
			actionResource.setDomain("authZ");
			actionResource.setMajorVersion(STANZA_DESC_MAJOR_VER);
			actionResource.setMinorVersion(STANZA_DESC_MINOR_VER);
			actionResource.setApplicationId(Long.parseLong("4112"));
			actionResource.setRootFlg("N");
			Document actionResourceDoc = BuildDocument();
			propMarshaller.marshal(actionResource, actionResourceDoc);
			request.add(actionResourceDoc);
			com.fedex.enterprise.security.cds.authZ.Resource actionStarResource = securityObjectFactory.createResource();
			actionStarResource.setResourceDesc(appId + " " + applicationName + " any action resource");
			actionStarResource.setResourceName(appId + "ACTION/*");
			actionStarResource.setDomain("authZ");
			actionStarResource.setMajorVersion(STANZA_DESC_MAJOR_VER);
			actionStarResource.setMinorVersion(STANZA_DESC_MINOR_VER);
			actionStarResource.setApplicationId(Long.parseLong("4112"));
			actionStarResource.setRootFlg("N");
			Document actionStarResourceDoc = BuildDocument();
			propMarshaller.marshal(actionStarResource, actionStarResourceDoc);
			request.add(actionStarResourceDoc);
			com.fedex.enterprise.security.cds.authZ.Resource resResource = securityObjectFactory.createResource();
			resResource.setResourceDesc(appId + " " + applicationName + " resource resource");
			resResource.setResourceName(appId + "RESOURCE/");
			resResource.setDomain("authZ");
			resResource.setMajorVersion(STANZA_DESC_MAJOR_VER);
			resResource.setMinorVersion(STANZA_DESC_MINOR_VER);
			resResource.setApplicationId(Long.parseLong("4112"));
			resResource.setRootFlg("N");
			Document resResourceDoc = BuildDocument();
			propMarshaller.marshal(resResource, resResourceDoc);
			request.add(resResourceDoc);
			com.fedex.enterprise.security.cds.authZ.Resource resStarResource = securityObjectFactory.createResource();
			resStarResource.setResourceDesc(appId + " " + applicationName + " any resource resource");
			resStarResource.setResourceName(appId + "RESOURCE/*");
			resStarResource.setDomain("authZ");
			resStarResource.setMajorVersion(STANZA_DESC_MAJOR_VER);
			resStarResource.setMinorVersion(STANZA_DESC_MINOR_VER);
			resStarResource.setApplicationId(Long.parseLong("4112"));
			resStarResource.setRootFlg("N");
			Document resStarResourceDoc = BuildDocument();
			propMarshaller.marshal(resStarResource, resStarResourceDoc);
			request.add(resStarResourceDoc);
			com.fedex.enterprise.security.cds.authZ.Resource roleResource = securityObjectFactory.createResource();
			roleResource.setResourceDesc(appId + " " + applicationName + " role resource");
			roleResource.setResourceName(appId + "ROLE/");
			roleResource.setDomain("authZ");
			roleResource.setMajorVersion(STANZA_DESC_MAJOR_VER);
			roleResource.setMinorVersion(STANZA_DESC_MINOR_VER);
			roleResource.setApplicationId(Long.parseLong("4112"));
			roleResource.setRootFlg("N");
			Document roleResourceDoc = BuildDocument();
			propMarshaller.marshal(roleResource, roleResourceDoc);
			request.add(roleResourceDoc);
			com.fedex.enterprise.security.cds.authZ.Resource roleStarResource = securityObjectFactory.createResource();
			roleStarResource.setResourceDesc(appId + " " + applicationName + " any role resource");
			roleStarResource.setResourceName(appId + "ROLE/*");
			roleStarResource.setDomain("authZ");
			roleStarResource.setMajorVersion(STANZA_DESC_MAJOR_VER);
			roleStarResource.setMinorVersion(STANZA_DESC_MINOR_VER);
			roleStarResource.setApplicationId(Long.parseLong("4112"));
			roleStarResource.setRootFlg("N");
			Document roleStarResourceDoc = BuildDocument();
			propMarshaller.marshal(roleStarResource, roleStarResourceDoc);
			request.add(roleStarResourceDoc);
			com.fedex.enterprise.security.cds.authZ.Resource policyResource = securityObjectFactory.createResource();
			policyResource.setResourceDesc(appId + " " + applicationName + " policy resource");
			policyResource.setResourceName(appId + "POLICY/");
			policyResource.setDomain("authZ");
			policyResource.setMajorVersion(STANZA_DESC_MAJOR_VER);
			policyResource.setMinorVersion(STANZA_DESC_MINOR_VER);
			policyResource.setApplicationId(Long.parseLong("4112"));
			policyResource.setRootFlg("N");
			Document policyResourceDoc = BuildDocument();
			propMarshaller.marshal(policyResource, policyResourceDoc);
			request.add(policyResourceDoc);
			com.fedex.enterprise.security.cds.authZ.Resource policyStarResource = securityObjectFactory.createResource();
			policyStarResource.setResourceDesc(appId + " " + applicationName + " any policy resource");
			policyStarResource.setResourceName(appId + "POLICY/*");
			policyStarResource.setDomain("authZ");
			policyStarResource.setMajorVersion(STANZA_DESC_MAJOR_VER);
			policyStarResource.setMinorVersion(STANZA_DESC_MINOR_VER);
			policyStarResource.setApplicationId(Long.parseLong("4112"));
			policyStarResource.setRootFlg("N");
			Document policyStarResourceDoc = BuildDocument();
			propMarshaller.marshal(policyStarResource, policyStarResourceDoc);
			request.add(policyStarResourceDoc);
			com.fedex.enterprise.security.cds.authZ.Resource reportResource = securityObjectFactory.createResource();
			reportResource.setResourceDesc(appId + " " + applicationName + " report resource");
			reportResource.setResourceName(appId + "REPORT/");
			reportResource.setDomain("authZ");
			reportResource.setMajorVersion(STANZA_DESC_MAJOR_VER);
			reportResource.setMinorVersion(STANZA_DESC_MINOR_VER);
			reportResource.setApplicationId(Long.parseLong("4112"));
			reportResource.setRootFlg("N");
			Document reportResourceDoc = BuildDocument();
			propMarshaller.marshal(reportResource, reportResourceDoc);
			request.add(reportResourceDoc);
			com.fedex.enterprise.security.cds.authZ.Resource reportStarResource = securityObjectFactory.createResource();
			reportStarResource.setResourceDesc(appId + " " + applicationName + " any report resource");
			reportStarResource.setResourceName(appId + "REPORT/*");
			reportStarResource.setDomain("authZ");
			reportStarResource.setMajorVersion(STANZA_DESC_MAJOR_VER);
			reportStarResource.setMinorVersion(STANZA_DESC_MINOR_VER);
			reportStarResource.setApplicationId(Long.parseLong("4112"));
			reportStarResource.setRootFlg("N");
			Document reportStarResourceDoc = BuildDocument();
			propMarshaller.marshal(reportStarResource, reportStarResourceDoc);
			request.add(reportStarResourceDoc);
			String callingApp = "4112";
			String desc = appId + " was setup by " + onBehalfOf + " from " + ("4112".equals("4112") ? "the ESC." : "App #4112");
			InsertRequest.InsertItem auditRecord = createStaticAuditRecord(appId, onBehalfOf, desc, "create", "resource");
			List<InsertRequest.InsertItem> auditRecords = new ArrayList();
			auditRecords.add(auditRecord);
			keys = cdsClient.insert(request, auditRecords, systemOverride);
			logger.info(new FedExLogEntry("Resource Keys: " + keys.size()));
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
		return keys;
	}

	public static List<ResourceData> RetrieveRootResourcesByNames(String appId) {
		logger.info(new FedExLogEntry("Retrieve Resources for appId by Name " + appId));
		if (cdsClient == null) {
			logger.warn(new FedExLogEntry("cdsClient is null! "));
		}
		List<ResourceData> response = new ArrayList();
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		DocumentBuilder builder;
		try {
			builder = factory.newDocumentBuilder();
		}
		catch (ParserConfigurationException e) {
			logger.error(new FedExLogEntry("Caught ParserConfigurationException in CdsSecurityResource RetrieveRootResourcesByNames new instance"), e);
			throw new RuntimeException(e.getMessage(), e);
		}
		Document document = builder.newDocument();
		Element root = document.createElement("ApplicationId");
		root.setTextContent(appId);
		document.appendChild(root);
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		EnrichedQueryRequest enrichedRequest = of.createEnrichedQueryRequest();
		enrichedRequest.setDomain("authZ");
		enrichedRequest.setName("getRootResources");
		enrichedRequest.setAny(document.getDocumentElement());
		EnrichedQueryResponse enrichedResponse = cdsClient.enrichedQuery(enrichedRequest);
		JAXBContext propertiesStanzaContext = null;
		Unmarshaller unmarshaller = null;
		try {
			propertiesStanzaContext = JAXBContext.newInstance(ResourceList.class);
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityResource RetrieveRootResourcesByNames new instance"), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		try {
			unmarshaller = propertiesStanzaContext.createUnmarshaller();
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityResource RetrieveRootResourcesByNames create unmarshaller"), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		List<Object> objects = enrichedResponse.getAny();
		Element docElement = (Element)objects.get(0);
		com.fedex.cds.plugin.jaxb.ObjectFactory objectProperty = new com.fedex.cds.plugin.jaxb.ObjectFactory();
		ResourceList resourceList = objectProperty.createResourceList();
		try {
			resourceList = (ResourceList)unmarshaller.unmarshal(docElement);
		}
		catch (JAXBException e) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityResource RetrieveRootResourcesByNames unmarshal"), e);
		}
		List<com.fedex.cds.plugin.jaxb.Resource> resources = resourceList.getResource();
		logger.warn(new FedExLogEntry("TOTAL  RESOURCES RECEIVED FROM ENRICHED QUERY RESPONSE = " + resources.size()));
		for (com.fedex.cds.plugin.jaxb.Resource resource : resources) {
			ResourceData newResource = new ResourceData();
			newResource.setDocId(resource.getResourceDocId());
			newResource.setResName(resource.getResourceName());
			newResource.setAppId(Long.toString(resource.getApplicationId()));
			newResource.setResDesc(resource.getResourceDesc());
			newResource.setRootFlg(resource.getRootFlg().charAt(0));
			response.add(newResource);
		}
		return response;
	}

	public static List<ResourceData> RetrieveByNames(String appId) {
		logger.info(new FedExLogEntry("Retrieve Resources for appId by Name " + appId));
		if (cdsClient == null) {
			logger.warn(new FedExLogEntry("cdsClient is null! "));
		}
		List<ResourceData> response = new ArrayList();
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		DocumentBuilder builder;
		try {
			builder = factory.newDocumentBuilder();
		}
		catch (ParserConfigurationException e) {
			logger.error(new FedExLogEntry("Caught ParserConfigurationException in CdsSecurityResource RetrieveByNames new document builder"), e);
			throw new RuntimeException(e.getMessage(), e);
		}
		Document document = builder.newDocument();
		Element root = document.createElement("ApplicationId");
		root.setTextContent(appId);
		document.appendChild(root);
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		EnrichedQueryRequest enrichedRequest = of.createEnrichedQueryRequest();
		enrichedRequest.setDomain("authZ");
		enrichedRequest.setName("getResources");
		enrichedRequest.setAny(document.getDocumentElement());
		EnrichedQueryResponse enrichedResponse = cdsClient.enrichedQuery(enrichedRequest);
		JAXBContext propertiesStanzaContext = null;
		Unmarshaller unmarshaller = null;
		try {
			propertiesStanzaContext = JAXBContext.newInstance(ResourceList.class);
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityResource RetrieveByNames new instace"), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		try {
			unmarshaller = propertiesStanzaContext.createUnmarshaller();
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityResource RetrieveByNames create unmarshaller"), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		List<Object> objects = enrichedResponse.getAny();
		Element docElement = (Element)objects.get(0);
		com.fedex.cds.plugin.jaxb.ObjectFactory objectProperty = new com.fedex.cds.plugin.jaxb.ObjectFactory();
		ResourceList resourceList = objectProperty.createResourceList();
		try {
			resourceList = (ResourceList)unmarshaller.unmarshal(docElement);
		}
		catch (JAXBException e) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityResource RetrieveByNames unmarshal"), e);
		}
		List<com.fedex.cds.plugin.jaxb.Resource> resources = resourceList.getResource();
		logger.warn(new FedExLogEntry("TOTAL  RESOURCES RECEIVED FROM ENRICHED QUERY RESPONSE = " + resources.size()));
		for (com.fedex.cds.plugin.jaxb.Resource resource : resources) {
			ResourceData newResource = new ResourceData();
			newResource.setDocId(resource.getResourceDocId());
			newResource.setResName(resource.getResourceName());
			newResource.setAppId(Long.toString(resource.getApplicationId()));
			newResource.setResDesc(resource.getResourceDesc());
			newResource.setRootFlg(resource.getRootFlg().charAt(0));
			response.add(newResource);
		}
		return response;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\cds\CdsSecurityResource.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */