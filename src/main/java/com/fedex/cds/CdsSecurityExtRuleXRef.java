package com.fedex.cds;

import com.fedex.common.icefaces.util.FacesUtils;
import com.fedex.ea.framework.securityapi.dao.esc.EscDaoException;
import com.fedex.enterprise.security.cds.authZ.ExtRuleXRef;
import com.fedex.enterprise.security.esc.view.model.WssoHandler;
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
import java.util.Iterator;
import java.util.List;

public class CdsSecurityExtRuleXRef
		extends CdsSecurityBase {
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(CdsSecurityExtRuleXRef.class);

	public static void Insert(ExtendedRuleXrefData newObject) {
		Insert(newObject, false);
	}

	public static void Insert(ExtendedRuleXrefData newObject, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		if (!systemOverride) {
			WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
			onBehalfOf = roleHandler.getUserId();
		}
		Insert(newObject, systemOverride, onBehalfOf, "");
	}

	public static void Insert(ExtendedRuleXrefData newObject, boolean systemOverride, String onBehalfOf, String appId) {
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
			ExtRuleXRef cdsExtendedRuleXRef = securityObjectFactory.createExtRuleXRef();
			cdsExtendedRuleXRef.setApplicationId(Long.parseLong(newObject.getAppId()));
			cdsExtendedRuleXRef.setDomain("authZ");
			cdsExtendedRuleXRef.setExtRuleDocId(newObject.getExtRuleDocId());
			cdsExtendedRuleXRef.setRuleDocId(newObject.getRuleDocId());
			cdsExtendedRuleXRef.setMajorVersion(STANZA_DESC_MAJOR_VER);
			cdsExtendedRuleXRef.setMinorVersion(STANZA_DESC_MINOR_VER);
			Document doc = BuildDocument();
			propMarshaller.marshal(cdsExtendedRuleXRef, doc);
			request.add(doc);
			String desc = "Extended Rule #" + cdsExtendedRuleXRef.getExtRuleDocId() + " was added to Rule #" + cdsExtendedRuleXRef.getRuleDocId() + " by " + onBehalfOf + " from " + (callingApp.equals("4112") ? "the ESC." : new StringBuilder().append("App #").append(callingApp).toString());
			InsertRequest.InsertItem auditRecord = createStaticAuditRecord(String.valueOf(cdsExtendedRuleXRef.getApplicationId()), onBehalfOf, desc, "modify", "extendedRule");
			List<InsertRequest.InsertItem> auditRecords = new ArrayList();
			auditRecords.add(auditRecord);
			cdsClient.insert(request, auditRecords, systemOverride);
		}
		catch (SoapFaultClientException sfx) {
			SoapFaultMessage.ThrowRuntimeException(sfx);
		}
		catch (JAXBException jbEx) {
			logger.warn(new FedExLogEntry("Caught JAXB Exception ex: " + jbEx.toString()));
			throw new RuntimeException(jbEx.getMessage(), jbEx);
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Caught general Exception ex: " + e.toString()));
			throw new RuntimeException(e.getMessage(), e);
		}
	}

	public static List<ExtendedRuleXrefData> retrieveForApplication(String appId, boolean mapObjects) throws EscDaoException {
		List<SecurityDataBaseClass> baseList = cdsClient.indexQuery("/extRuleXRef/@ApplicationId", CdsClient.QUERY_COMPARE.equals, appId, "authZ", CdsSecurityBase.STANZAS.extRuleXRef, "authZ", CdsSecurityBase.STANZAS.extRuleXRef, mapObjects);
		return castList(baseList);
	}

	private static List<ExtendedRuleXrefData> castList(List<SecurityDataBaseClass> tempList) {
		List<ExtendedRuleXrefData> list = new ArrayList(tempList.size());
		for (SecurityDataBaseClass base : tempList) {
			list.add((ExtendedRuleXrefData)base);
		}
		return list;
	}

	public static List<ExtendedRuleXrefData> Retrieve(String appId, Bookmark bookmarkId) {
		String bookmark = "";
		List<ExtendedRuleXrefData> response = new ArrayList();
		int totalDocCount = 0;
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		if (bookmarkId == null) {
			bookmarkId = new Bookmark();
			bookmarkId.setBookmark("5120135");
		}
		StanzaIdType stanzaId = of.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("extRuleXRef");
		StanzaIdType indexStanzaId = of.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("extRuleXRef");
		Unmarshaller unmarshaller;
		do {
			IndexQueryResponse indexResponse = cdsClient.indexQuery(BuildIndexQuery(Long.parseLong(appId), EMPTY_VALUE.longValue()), stanzaId, indexStanzaId, bookmark);
			List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
			JAXBContext propertiesStanzaContext = null;
			unmarshaller = null;
			try {
				propertiesStanzaContext = JAXBContext.newInstance(ExtRuleXRef.class);
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in Retrieve CdsSecurityExtRuleXRef new Instance"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			try {
				unmarshaller = propertiesStanzaContext.createUnmarshaller();
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in Retrieve CdsSecurityExtRuleXRef unmarshaller"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
				for (Iterator i$ = queryItem.getKeyedStanzas().iterator(); i$.hasNext(); ) {
					KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
					totalDocCount++;
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						ExtRuleXRef currentXRef = null;
						try {
							currentXRef = (ExtRuleXRef)unmarshaller.unmarshal(docElement);
							ExtendedRuleXrefData newXRefData = new ExtendedRuleXrefData();
							newXRefData.setDocId(keyedStanzas.getKey());
							newXRefData.setExtRuleDocId(currentXRef.getExtRuleDocId());
							newXRefData.setRuleDocId(currentXRef.getRuleDocId());
							newXRefData.setAppId(appId);
							response.add(newXRefData);
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("Caught JAXBException in Retrieve CdsSecurityExtRuleXRef unmarshal"), e);
						}
						continue;
					}
				}
				bookmark = queryItem.getPaging().getBookmark();
			}
		}
		while ((!"".equals(bookmark)) && (bookmarkId.getBookmark() == "5120135"));
		bookmarkId.setBookmark(bookmark);
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR XRef for APP = " + totalDocCount));
		return response;
	}

	public static ExtendedRuleXrefData RetrieveOne(long docId) {
		Unmarshaller unmarshaller = null;
		JAXBContext extRefStanzaContext = null;
		ExtendedRuleXrefData ruleData = null;
		try {
			extRefStanzaContext = JAXBContext.newInstance(ExtRuleXRef.class);
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in RetrieveOne CdsSecurityExtRuleXRef new Instance"), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		try {
			unmarshaller = extRefStanzaContext.createUnmarshaller();
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in RetrieveOne CdsSecurityExtRuleXRef create unmarshaller"), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		try {
			List<Long> keys = new ArrayList();
			keys.add(Long.valueOf(docId));
			KeyQueryRequest request = buildKeyQueryRequest(keys, "extRuleXRef");
			KeyQueryResponse response = cdsClient.keyQuery(request);
			for (Iterator i$ = response.getKeyedStanzas().iterator(); i$.hasNext(); ) {
				KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
				List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
				for (KeyedStanzasType.Stanza s : stanzaList) {
					Element docElement = s.getAny();
					ExtRuleXRef currentXRef = null;
					try {
						currentXRef = (ExtRuleXRef)unmarshaller.unmarshal(docElement);
						ruleData = new ExtendedRuleXrefData();
						ruleData.setDocId(keyedStanzas.getKey());
						ruleData.setExtRuleDocId(currentXRef.getExtRuleDocId());
						ruleData.setRuleDocId(currentXRef.getRuleDocId());
						ruleData.setAppId(Long.toString(currentXRef.getApplicationId()));
					}
					catch (JAXBException e) {
						logger.error(new FedExLogEntry("Caught JAXBException in RetrieveOne CdsSecurityExtRuleXRef unmarshal"), e);
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

	public static List<ExtendedRuleXrefData> Retrieve(long ruleID, Bookmark bookmarkId) {
		String bookmark = "";
		List<ExtendedRuleXrefData> response = new ArrayList();
		int totalDocCount = 0;
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		if (bookmarkId == null) {
			bookmarkId = new Bookmark();
			bookmarkId.setBookmark("5120135");
		}
		StanzaIdType stanzaId = of.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("extRuleXRef");
		StanzaIdType indexStanzaId = of.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("extRuleXRef");
		Unmarshaller unmarshaller;
		do {
			IndexQueryResponse indexResponse = cdsClient.indexQuery(BuildIndexQuery(EMPTY_VALUE.longValue(), ruleID), stanzaId, indexStanzaId, bookmark);
			List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
			JAXBContext propertiesStanzaContext = null;
			unmarshaller = null;
			try {
				propertiesStanzaContext = JAXBContext.newInstance(ExtRuleXRef.class);
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in Retrieve CdsSecurityExtRuleXRef new instance"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			try {
				unmarshaller = propertiesStanzaContext.createUnmarshaller();
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in Retrieve CdsSecurityExtRuleXRef create unmarshaller"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
				for (Iterator i$ = queryItem.getKeyedStanzas().iterator(); i$.hasNext(); ) {
					KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
					totalDocCount++;
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						ExtRuleXRef currentXRef = null;
						try {
							currentXRef = (ExtRuleXRef)unmarshaller.unmarshal(docElement);
							ExtendedRuleXrefData newXRefData = new ExtendedRuleXrefData();
							newXRefData.setDocId(keyedStanzas.getKey());
							newXRefData.setExtRuleDocId(currentXRef.getExtRuleDocId());
							newXRefData.setRuleDocId(currentXRef.getRuleDocId());
							newXRefData.setAppId(Long.toString(currentXRef.getApplicationId()));
							response.add(newXRefData);
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("Caught JAXBException in Retrieve CdsSecurityExtRuleXRef unmarshal"), e);
						}
						continue;
					}
				}
				bookmark = queryItem.getPaging().getBookmark();
			}
		}
		while ((!"".equals(bookmark)) && (bookmarkId.getBookmark() == "5120135"));
		bookmarkId.setBookmark(bookmark);
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR XRef for Rule = " + totalDocCount));
		return response;
	}

	private static List<IndexElementType> BuildIndexQuery(long appID, long ruleID) {
		List<IndexElementType> indexElements = new ArrayList();
		if (appID != EMPTY_VALUE.longValue()) {
			IndexElementType appId = new IndexElementType();
			appId.setXpath("/extRuleXRef/@ApplicationId");
			appId.setComparison("equals");
			appId.setValue(Long.toString(appID));
			indexElements.add(appId);
		}
		if (ruleID != EMPTY_VALUE.longValue()) {
			IndexElementType ruleIdentifier = new IndexElementType();
			ruleIdentifier.setXpath("/extRuleXRef/@RuleDocId");
			ruleIdentifier.setComparison("equals");
			ruleIdentifier.setValue(Long.toString(ruleID));
			indexElements.add(ruleIdentifier);
		}
		return indexElements;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\cds\CdsSecurityExtRuleXRef.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */