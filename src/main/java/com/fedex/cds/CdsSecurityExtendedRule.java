package com.fedex.cds;

import com.fedex.common.icefaces.util.FacesUtils;
import com.fedex.ea.framework.securityapi.dao.esc.EscDaoException;
import com.fedex.enterprise.security.cds.authZ.AuditRecord;
import com.fedex.enterprise.security.cds.authZ.ExtendedRule;
import com.fedex.enterprise.security.esc.view.model.EscBean;
import com.fedex.enterprise.security.esc.view.model.WssoHandler;
import com.fedex.enterprise.security.rule.ExtendedRuleData;
import com.fedex.enterprise.security.rule.ExtendedRuleXrefData;
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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

public class CdsSecurityExtendedRule
		extends CdsSecurityBase {
	private static final String EXTENDED_RULE = "Extended Rule #";
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(CdsSecurityExtendedRule.class);

	public static long Insert(ExtendedRuleData newObject) {
		return Insert(newObject, false);
	}

	public static long Insert(ExtendedRuleData newObject, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		if (!systemOverride) {
			WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
			onBehalfOf = roleHandler.getUserId();
		}
		return Insert(newObject, systemOverride, onBehalfOf, "");
	}

	public static long Insert(ExtendedRuleData newObject, boolean systemOverride, String onBehalfOf, String appId) {
		List<Long> keys = null;
		List<Document> request = new ArrayList();
		String callingApp = "";
		if (EscUtils.isNullOrBlank(appId)) {
			callingApp = "4112";
		}
		else {
			callingApp = appId;
		}
		try {
			com.fedex.enterprise.security.cds.authZ.ObjectFactory securityObjectFactory = new com.fedex.enterprise.security.cds.authZ.ObjectFactory();
			JAXBContext propJaxbContext = JAXBContext.newInstance("com.fedex.enterprise.security.cds.authZ");
			Marshaller propMarshaller = propJaxbContext.createMarshaller();
			ExtendedRule cdsExtendedRule = securityObjectFactory.createExtendedRule();
			cdsExtendedRule.setApplicationId(Long.parseLong(newObject.getAppId()));
			cdsExtendedRule.setDomain("authZ");
			cdsExtendedRule.setExtendedRuleKey(newObject.getExtRuleKey());
			cdsExtendedRule.setExtendedRuleOperator(newObject.getExtRuleOperator());
			cdsExtendedRule.setExtendedRuleValue(newObject.getExtRuleValue());
			cdsExtendedRule.setExtendedRuleValueType(newObject.getExtRuleType());
			cdsExtendedRule.setMajorVersion(STANZA_DESC_MAJOR_VER);
			cdsExtendedRule.setMinorVersion(STANZA_DESC_MINOR_VER);
			Document doc = BuildDocument();
			String extRule = "'" + newObject.getExtRuleKey() + " " + newObject.getExtRuleOperator() + " " + newObject.getExtRuleValue() + "'";
			propMarshaller.marshal(cdsExtendedRule, doc);
			request.add(doc);
			keys = cdsClient.insert(request, null, systemOverride);
			String desc = "Extended Rule #" + extRule + " was added by " + onBehalfOf + " from " + (callingApp.equals("4112") ? "the ESC." : new StringBuilder().append("App #").append(callingApp).toString());
			AuditRecord auditRecord = createStaticAuditRecordObject(cdsExtendedRule.getApplicationId() + "", onBehalfOf, desc, "create", "extendedRule");
			CdsSecurityAuditReport.Insert(auditRecord, true);
		}
		catch (SoapFaultClientException sfx) {
			throw sfx;
		}
		catch (JAXBException jbEx) {
			logger.warn(new FedExLogEntry("Caught JAXB Exception ex: " + jbEx.toString()));
			throw new RuntimeException(jbEx.getMessage(), jbEx);
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Caught general Exception ex: " + e.toString()));
			throw new RuntimeException(e.getMessage(), e);
		}
		return keys.get(0).longValue();
	}

	public static void Delete(long DocId) {
		Delete(DocId, false);
	}

	public static void Delete(long DocId, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		if (!systemOverride) {
			WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
			onBehalfOf = roleHandler.getUserId();
		}
		EscBean escBean = (EscBean)FacesUtils.getManagedBean("escBean");
		String appId = escBean.getSelectedSymAppId();
		Delete(DocId, false, onBehalfOf, appId);
	}

	public static void Delete(long DocId, boolean systemOverride, String onBehalfOf, String appId) {
		String callingApp = appId;
		List<Long> extRules = new ArrayList();
		extRules.add(Long.valueOf(DocId));
		List<ExtendedRuleData> objectToDelete = Retrieve(extRules);
		List<ExtendedRuleXrefData> extRuleXRef = CdsSecurityExtRuleXRef.Retrieve(DocId, new Bookmark());
		List<InsertRequest.InsertItem> auditRecords = new ArrayList();
		List<Long> extRuleXrefKeys = new ArrayList();
		if ((objectToDelete != null) && (!objectToDelete.isEmpty()) &&
		    (extRuleXRef != null) && (!extRuleXRef.isEmpty())) {
			for (ExtendedRuleXrefData xref : extRuleXRef) {
				String desc2 = "Extended Rule #" + xref.getDocId() + " was removed from Rule # " + EscUtils.getRuleNameByDocId(DocId, appId) + " by the ESC due to the deletion of the extended rule.";
				InsertRequest.InsertItem item = createStaticAuditRecord(objectToDelete.get(0).getAppId(), onBehalfOf, desc2, "delete", "extRuleXRef");
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
		String desc = "Extended Rule #" + DocId + " was deleted by " + onBehalfOf + " from " + (callingApp.equals("4112") ? "the ESC." : new StringBuilder().append("App #").append(callingApp).toString());
		InsertRequest.InsertItem auditRecord = createStaticAuditRecord(appId, onBehalfOf, desc, "delete", "extendedRule");
		Delete(Long.valueOf(DocId), "extendedRule", auditRecord, systemOverride);
	}

	public static void Update(ExtendedRuleData objectToUpdate) {
		Update(objectToUpdate, false);
	}

	public static void Update(ExtendedRuleData objectToUpdate, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		if (!systemOverride) {
			WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
			onBehalfOf = roleHandler.getUserId();
		}
		Update(objectToUpdate, false, onBehalfOf, "");
	}

	public static void Update(ExtendedRuleData objectToUpdate, boolean systemOverride, String onBehalfOf, String appId) {
		String callingApp = "";
		if (EscUtils.isNullOrBlank(appId)) {
			callingApp = "4112";
		}
		else {
			callingApp = appId;
		}
		HashMap<String, String> xpathList = new HashMap();
		xpathList.put("/extendedRule/@ExtendedRuleKey", objectToUpdate.getExtRuleKey());
		xpathList.put("/extendedRule/@ExtendedRuleOperator", objectToUpdate.getExtRuleOperator());
		xpathList.put("/extendedRule/@ExtendedRuleValueType", objectToUpdate.getExtRuleType());
		xpathList.put("/extendedRule/@ExtendedRuleValue", objectToUpdate.getExtRuleValue());
		String desc = "Extended Rule #" + objectToUpdate.getDocId() + " was modified by " + onBehalfOf + " from " + (callingApp.equals("4112") ? "the ESC." : new StringBuilder().append("App #").append(callingApp).toString());
		InsertRequest.InsertItem auditRecord = createStaticAuditRecord(objectToUpdate.getAppId(), onBehalfOf, desc, "modify", "extendedRule");
		cdsClient.update(xpathList, objectToUpdate.getDocId(), "authZ", "extendedRule", auditRecord, false);
	}

	public static List<ExtendedRuleData> retrieve(List<Long> xrefKeys, boolean mapObjects) throws EscDaoException {
		return castList(cdsClient.keyQuery(xrefKeys, "authZ", CdsSecurityBase.STANZAS.extendedRule, mapObjects));
	}

	private static List<ExtendedRuleData> castList(List<SecurityDataBaseClass> tempList) {
		List<ExtendedRuleData> list = new ArrayList(tempList.size());
		for (SecurityDataBaseClass base : tempList) {
			list.add((ExtendedRuleData)base);
		}
		return list;
	}

	public static List<ExtendedRuleData> Retrieve(List<Long> keys) {
		Unmarshaller unmarshaller = null;
		JAXBContext extRefStanzaContext = null;
		List<ExtendedRuleData> returnList = new ArrayList();
		if (!keys.isEmpty()) {
			try {
				extRefStanzaContext = JAXBContext.newInstance(ExtendedRule.class);
				unmarshaller = extRefStanzaContext.createUnmarshaller();
				Iterator<Long> it = keys.iterator();
				Iterator i$;
				KeyedStanzasType keyedStanzas;
				do {
					List<Long> listOfKeys = new ArrayList();
					for (int counter = 0; counter < 500; counter++) {
						if (it.hasNext()) {
							listOfKeys.add(it.next());
						}
					}
					KeyQueryRequest request = buildKeyQueryRequest(listOfKeys, "extendedRule");
					KeyQueryResponse response = cdsClient.keyQuery(request);
					for (i$ = response.getKeyedStanzas().iterator(); i$.hasNext(); ) {
						keyedStanzas = (KeyedStanzasType)i$.next();
						List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
						for (KeyedStanzasType.Stanza s : stanzaList) {
							Element docElement = s.getAny();
							ExtendedRule currentRule = null;
							try {
								currentRule = (ExtendedRule)unmarshaller.unmarshal(docElement);
								ExtendedRuleData newExtendedRuleData = new ExtendedRuleData();
								newExtendedRuleData.setAppId(Long.toString(currentRule.getApplicationId()));
								newExtendedRuleData.setDocId(keyedStanzas.getKey());
								newExtendedRuleData.setExtRuleKey(currentRule.getExtendedRuleKey());
								newExtendedRuleData.setExtRuleOperator(currentRule.getExtendedRuleOperator());
								newExtendedRuleData.setExtRuleType(currentRule.getExtendedRuleValueType());
								newExtendedRuleData.setExtRuleValue(currentRule.getExtendedRuleValue());
								returnList.add(newExtendedRuleData);
							}
							catch (JAXBException e) {
								logger.error(new FedExLogEntry("Caught JAXBException in getCustomAuthzByKey unmarshal"), e);
							}
							continue;
						}
					}
				}
				while (it.hasNext());
			}
			catch (SoapFaultClientException sfx) {
				throw sfx;
			}
			catch (Exception e) {
				logger.warn(new FedExLogEntry("Caught general Exception ex: " + e.toString()));
				throw new RuntimeException(e);
			}
		}
		return returnList;
	}

	public static List<ExtendedRuleData> Retrieve(String appId, Bookmark bookmarkId) {
		if (bookmarkId == null) {
			bookmarkId = new Bookmark();
			bookmarkId.setBookmark("5120135");
		}
		String bookmark = "";
		List<ExtendedRuleData> response = new ArrayList();
		int totalDocCount = 0;
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		StanzaIdType stanzaId = of.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("extendedRule");
		StanzaIdType indexStanzaId = of.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("extendedRule");
		Unmarshaller unmarshaller;
		do {
			IndexQueryResponse indexResponse = cdsClient.indexQuery(BuildIndexQuery(Integer.parseInt(appId)), stanzaId, indexStanzaId, bookmark);
			List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
			JAXBContext propertiesStanzaContext = null;
			unmarshaller = null;
			try {
				propertiesStanzaContext = JAXBContext.newInstance(ExtendedRule.class);
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in Retrieve new instance"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			try {
				unmarshaller = propertiesStanzaContext.createUnmarshaller();
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in Retrieve create unmarshaller"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
				for (Iterator i$ = queryItem.getKeyedStanzas().iterator(); i$.hasNext(); ) {
					KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
					totalDocCount++;
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						ExtendedRule currentExtendedRule = null;
						try {
							currentExtendedRule = (ExtendedRule)unmarshaller.unmarshal(docElement);
							ExtendedRuleData newRuleData = new ExtendedRuleData();
							newRuleData.setAppId(Long.toString(currentExtendedRule.getApplicationId()));
							newRuleData.setExtRuleKey(currentExtendedRule.getExtendedRuleKey());
							newRuleData.setExtRuleValue(currentExtendedRule.getExtendedRuleValue());
							newRuleData.setExtRuleType(currentExtendedRule.getExtendedRuleValueType());
							newRuleData.setExtRuleOperator(currentExtendedRule.getExtendedRuleOperator());
							newRuleData.setDocId(keyedStanzas.getKey());
							response.add(newRuleData);
							logger.info(new FedExLogEntry("ExtendedRule: " + newRuleData));
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("Caught JAXBException in Retrieve unmarshal"), e);
						}
						continue;
					}
				}
				bookmark = queryItem.getPaging().getBookmark();
			}
		}
		while (!"".equals(bookmark));
		bookmarkId.setBookmark(bookmark);
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR ExtendedRule = " + totalDocCount));
		return response;
	}

	private static List<IndexElementType> BuildIndexQuery(int appID) {
		List<IndexElementType> indexElements = new ArrayList();
		IndexElementType appId = new IndexElementType();
		appId.setXpath("/extendedRule/@ApplicationId");
		appId.setComparison("equals");
		appId.setValue(Integer.toString(appID));
		indexElements.add(appId);
		return indexElements;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\cds\CdsSecurityExtendedRule.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */