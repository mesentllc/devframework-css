package com.fedex.cds;

import com.fedex.common.icefaces.util.FacesUtils;
import com.fedex.ea.framework.securityapi.dao.esc.EscDaoException;
import com.fedex.enterprise.security.action.ActionData;
import com.fedex.enterprise.security.action.ActionService;
import com.fedex.enterprise.security.cds.authZ.Action;
import com.fedex.enterprise.security.esc.view.model.WssoHandler;
import com.fedex.enterprise.security.rule.ExtendedRuleXrefData;
import com.fedex.enterprise.security.rule.RuleData;
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
import javax.xml.ws.soap.SOAPFaultException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class CdsSecurityAction
		extends CdsSecurityBase
		implements ActionService {
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(CdsSecurityAction.class);

	public void deleteAction(ActionData action) {
		deleteAction(action, false);
	}

	public void deleteAction(ActionData action, boolean systemOverride) {
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
		deleteAction(action, systemOverride, onBehalfOf, "");
	}

	public void deleteAction(ActionData action, boolean systemOverride, String onBehalfOf, String appId) {
		String callingApp = "";
		try {
			if (EscUtils.isNullOrBlank(appId)) {
				callingApp = "4112";
			}
			else {
				callingApp = appId;
			}
			List<RuleData> rules = CdsSecurityRule.Retrieve(action.getAppId(), new Bookmark());
			List<InsertRequest.InsertItem> auditRecordsForRules = new ArrayList();
			List<InsertRequest.InsertItem> auditRecords = new ArrayList();
			List<Long> ruleKeys = new ArrayList();
			List<Long> extRuleXrefKeys = new ArrayList();
			Iterator i$;
			if ((rules != null) && (!rules.isEmpty())) {
				for (i$ = rules.iterator(); i$.hasNext(); ) {
					RuleData rule = (RuleData)i$.next();
					if (rule.getActionDocId() == action.getDocId()) {
						ruleKeys.add(Long.valueOf(rule.getDocId()));
						String ruleNm = rule.getRoleNm() + " " + rule.getGrantMsg() + " " + rule.getActionNm() + " " + rule.getResourceNm();
						String desc = "Rule ' " + ruleNm + "' was removed by the ESC due to the deletion of action " + action.getActionNm() + ".";
						InsertRequest.InsertItem auditItem = createAuditRecord(action.getAppId(), onBehalfOf, desc, "delete", "rule");
						auditRecordsForRules.add(auditItem);
						List<ExtendedRuleXrefData> extRuleXRef = CdsSecurityExtRuleXRef.Retrieve(rule.getDocId(), new Bookmark());
						for (ExtendedRuleXrefData xref : extRuleXRef) {
							String desc2 = "Extended Rule #" + xref.getDocId() + " was removed from Rule # " + rule.getDocId() + " by the ESC due to the deletion of action " + action.getActionNm() + ".";
							InsertRequest.InsertItem item = createAuditRecord(action.getAppId(), onBehalfOf, desc2, "delete", "extRuleXRef");
							auditRecords.add(item);
							extRuleXrefKeys.add(Long.valueOf(xref.getDocId()));
						}
					}
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
			try {
				if ((ruleKeys != null) && (!ruleKeys.isEmpty())) {
					CdsSecurityRule.Delete(ruleKeys, "rule", auditRecordsForRules);
				}
			}
			catch (Exception e) {
				logger.warn(new FedExLogEntry("WARNING: unable to properly delete rules for the action in question."));
			}
			String desc = action.getActionNm() + " was deleted by " + onBehalfOf + " from " + (callingApp.equals("4112") ? "the ESC." : new StringBuilder().append("App #").append(callingApp).toString());
			InsertRequest.InsertItem auditRecord = createAuditRecord(action.getAppId(), onBehalfOf, desc, "delete", "action");
			Delete(action.getDocId(), "action", auditRecord, systemOverride);
		}
		catch (SecurityException se) {
			throw new RuntimeException(se.getMessage(), se);
		}
	}

	public long insertAction(ActionData action) {
		return insertAction(action, false);
	}

	public long insertAction(ActionData action, boolean systemOverride) {
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
		return insertAction(action, systemOverride, onBehalfOf, "");
	}

	public long insertAction(ActionData action, boolean systemOverride, String onBehalfOf, String appId) {
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
			Action cdsAction = securityObjectFactory.createAction();
			String description = action.getActionDesc();
			if ((description == null) || (description.isEmpty())) {
				description = "NA";
			}
			cdsAction.setActionDesc(description);
			cdsAction.setActionName(action.getActionNm());
			cdsAction.setDomain("authZ");
			cdsAction.setMajorVersion(STANZA_DESC_MAJOR_VER);
			cdsAction.setMinorVersion(STANZA_DESC_MINOR_VER);
			cdsAction.setApplicationId(Long.parseLong(action.getAppId()));
			Document doc = BuildDocument();
			propMarshaller.marshal(cdsAction, doc);
			request.add(doc);
			String desc = action.getActionNm() + " was created by " + onBehalfOf + " from " + (callingApp.equals("4112") ? "the ESC." : new StringBuilder().append("App #").append(callingApp).toString());
			InsertRequest.InsertItem auditRecord = createAuditRecord(action.getAppId(), onBehalfOf, desc, "create", "action");
			List<InsertRequest.InsertItem> auditRecords = new ArrayList();
			auditRecords.add(auditRecord);
			List<Long> keys = cdsClient.insert(request, auditRecords, systemOverride);
			action.setDocId(keys.get(0).longValue());
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
		return action.getDocId();
	}

	public void updateAction(ActionData action) {
		updateAction(action, false);
	}

	public void updateAction(ActionData action, boolean systemOverride) {
		WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
		String onBehalfOf = "APP4112";
		if (!systemOverride) {
			onBehalfOf = roleHandler.getUserId();
		}
		updateAction(action, systemOverride, onBehalfOf, "");
	}

	public void updateAction(ActionData action, boolean systemOverride, String onBehalfOf, String appId) {
		String callingApp = "";
		if (EscUtils.isNullOrBlank(appId)) {
			callingApp = "4112";
		}
		else {
			callingApp = appId;
		}
		HashMap<String, String> xpathList = new HashMap();
		String description = action.getActionDesc();
		if ((description == null) || (description.isEmpty())) {
			description = "NA";
		}
		xpathList.put("/action/@ActionDesc", description);
		xpathList.put("/action/@ActionName", action.getActionNm());
		String desc = action.getActionNm() + " was modified by " + onBehalfOf + " from " + (callingApp.equals("4112") ? "the ESC." : new StringBuilder().append("App #").append(callingApp).toString());
		InsertRequest.InsertItem auditRecord = createAuditRecord(action.getAppId(), onBehalfOf, desc, "modify", "action");
		cdsClient.update(xpathList, action.getDocId(), "authZ", "action", auditRecord, systemOverride);
	}

	private static List<IndexElementType> BuildIndexQuery(int appID, String partialActionName) {
		List<IndexElementType> indexElements = new ArrayList();
		IndexElementType appId = new IndexElementType();
		appId.setXpath("/action/@ApplicationId");
		appId.setComparison("equals");
		appId.setValue(Integer.toString(appID));
		indexElements.add(appId);
		if (null != partialActionName) {
			IndexElementType actionName = new IndexElementType();
			actionName.setXpath("/action/@ActionName");
			if ("*".equalsIgnoreCase(partialActionName)) {
				actionName.setComparison("equals");
				actionName.setValue(partialActionName);
			}
			else {
				actionName.setComparison("like");
				actionName.setValue(partialActionName + "%");
			}
			indexElements.add(actionName);
		}
		return indexElements;
	}

	public static ActionData getActionByKey(Long docId) {
		Unmarshaller unmarshaller = null;
		JAXBContext actionStanzaContext = null;
		try {
			actionStanzaContext = JAXBContext.newInstance(Action.class);
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Error in the getActionByKey new instance"), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		try {
			unmarshaller = actionStanzaContext.createUnmarshaller();
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Error in the getActionByKey create unmarshaller"), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		ActionData actionData = new ActionData();
		List<Long> keyList = new ArrayList();
		keyList.add(docId);
		KeyQueryRequest request = buildKeyQueryRequest(keyList, "action");
		KeyQueryResponse response = cdsClient.keyQuery(request);
		for (Iterator i$ = response.getKeyedStanzas().iterator(); i$.hasNext(); ) {
			KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
			List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
			for (KeyedStanzasType.Stanza s : stanzaList) {
				Element docElement = s.getAny();
				Action action;
				try {
					action = (Action)unmarshaller.unmarshal(docElement);
					actionData.setAppId(String.valueOf(action.getApplicationId()));
					actionData.setActionDesc(action.getActionDesc());
					actionData.setActionNm(action.getActionName());
					actionData.setDocId(keyedStanzas.getKey());
				}
				catch (JAXBException e) {
					logger.error(new FedExLogEntry("Error in the getActionByKey unmarshal"), e);
				}
				continue;
			}
		}
		return actionData;
	}

	public ActionData retrieveByName(String actionName, String appId)
			throws EscDaoException {
		List<SecurityDataBaseClass> dataList = cdsClient.indexQuery("/action/@ApplicationId", CdsClient.QUERY_COMPARE.equals, appId, "/action/@ActionName", CdsClient.QUERY_COMPARE.equals, actionName, "authZ", CdsSecurityBase.STANZAS.action, "authZ", CdsSecurityBase.STANZAS.action, true);
		if (dataList.size() == 1) {
			return (ActionData)dataList.get(0);
		}
		return null;
	}

	public static Map<Long, String> retrieveNames(List<Long> actionIds) throws EscDaoException {
		HashMap<Long, String> actionList = new HashMap();
		List<ActionData> actionDataList = retrieve(actionIds, true);
		for (ActionData actionData : actionDataList) {
			actionList.put(Long.valueOf(actionData.getDocId()), actionData.getActionNm());
		}
		return actionList;
	}

	public static List<ActionData> retrieve(List<Long> actionIds, boolean mapObjects) throws EscDaoException {
		return castList(cdsClient.keyQuery(actionIds, "authZ", CdsSecurityBase.STANZAS.action, mapObjects));
	}

	private static List<ActionData> castList(List<SecurityDataBaseClass> tempList) {
		List<ActionData> list = new ArrayList(tempList.size());
		for (SecurityDataBaseClass base : tempList) {
			list.add((ActionData)base);
		}
		return list;
	}

	public static Map<Long, String> getActionNamesByKeys(List<Long> docIds) {
		if ((docIds == null) || (docIds.isEmpty())) {
			return Collections.emptyMap();
		}
		Unmarshaller unmarshaller = null;
		JAXBContext actionStanzaContext = null;
		try {
			actionStanzaContext = JAXBContext.newInstance(Action.class);
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Error in the getActionNamesByKeys new instance"), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		try {
			unmarshaller = actionStanzaContext.createUnmarshaller();
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Error in the getActionNamesByKeys unmarshaller"), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		HashMap<Long, String> actionList = new HashMap();
		KeyQueryRequest request = buildKeyQueryRequest(docIds, "action");
		KeyQueryResponse response = cdsClient.keyQuery(request);
		for (Iterator i$ = response.getKeyedStanzas().iterator(); i$.hasNext(); ) {
			KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
			List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
			for (KeyedStanzasType.Stanza s : stanzaList) {
				Element docElement = s.getAny();
				Action action;
				try {
					action = (Action)unmarshaller.unmarshal(docElement);
					actionList.put(keyedStanzas.getKey(), action.getActionName());
				}
				catch (JAXBException e) {
					logger.error(new FedExLogEntry("Error in the getActionNamesByKeys unmarshal"), e);
				}
				continue;
			}
		}
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR ACTION NAMES = " + actionList.size()));
		return actionList;
	}

	public List<ActionData> getActionsForApplication(String appId, Bookmark bookmarkId) {
		return getActionsForApplicationByPartialActionName(appId, null, bookmarkId);
	}

	public List<ActionData> getActionsForApplicationByPartialActionName(String appId, String partActionNm, Bookmark bookmarkId) {
		String bookmark = "";
		List<ActionData> response = new ArrayList();
		int totalDocCount = 0;
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		if (bookmarkId == null) {
			bookmarkId = new Bookmark();
			bookmarkId.setBookmark("5120135");
		}
		StanzaIdType stanzaId = of.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("action");
		StanzaIdType indexStanzaId = of.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("action");
		Unmarshaller unmarshaller;
		do {
			IndexQueryResponse indexResponse = cdsClient.indexQuery(BuildIndexQuery(Integer.parseInt(appId), partActionNm), stanzaId, indexStanzaId, bookmark);
			List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
			JAXBContext propertiesStanzaContext = null;
			unmarshaller = null;
			try {
				propertiesStanzaContext = JAXBContext.newInstance(Action.class);
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Error in the getActionsForApplicationByPartialActionName newInstance"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			try {
				unmarshaller = propertiesStanzaContext.createUnmarshaller();
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Error in the getActionsForApplicationByPartialActionName unmarshaller"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
				for (Iterator i$ = queryItem.getKeyedStanzas().iterator(); i$.hasNext(); ) {
					KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
					totalDocCount++;
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						Action currentAction = null;
						try {
							currentAction = (Action)unmarshaller.unmarshal(docElement);
							ActionData newActionData = new ActionData();
							newActionData.setActionDesc(currentAction.getActionDesc());
							newActionData.setActionNm(currentAction.getActionName());
							newActionData.setAppId(appId);
							newActionData.setDocId(keyedStanzas.getKey());
							response.add(newActionData);
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("Error in the getActionsForApplicationByPartialActionName unmarshal action"), e);
						}
						continue;
					}
				}
				bookmark = queryItem.getPaging().getBookmark();
			}
		}
		while ((!"".equals(bookmark)) && (bookmarkId.getBookmark() == "5120135"));
		bookmarkId.setBookmark(bookmark);
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR ACTIONS = " + totalDocCount));
		return response;
	}

	public ActionData getAction(long docId) {
		return null;
	}
}
