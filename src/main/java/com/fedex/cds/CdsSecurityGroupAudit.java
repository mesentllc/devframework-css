package com.fedex.cds;

import com.fedex.common.icefaces.util.FacesUtils;
import com.fedex.enterprise.security.esc.view.model.WssoHandler;
import com.fedex.enterprise.security.group.audits.GroupAudit;
import com.fedex.enterprise.security.group.audits.GroupAuditData;
import com.fedex.enterprise.security.utils.EscUtils;
import com.fedex.framework.cds.IndexElementType;
import com.fedex.framework.cds.IndexQueryResponse;
import com.fedex.framework.cds.KeyedStanzasType;
import com.fedex.framework.cds.ObjectFactory;
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
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.ws.soap.SOAPFaultException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Iterator;
import java.util.List;

public class CdsSecurityGroupAudit extends CdsSecurityBase {
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(CdsSecurityGroupAudit.class);

	public long insertGroupAudit(GroupAuditData groupAuditData) {
		return insertGroupAudit(groupAuditData, false);
	}

	public long insertGroupAudit(GroupAuditData groupAuditData, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		try {
			if (!systemOverride) {
				WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
				onBehalfOf = roleHandler.getUserId();
			}
		}
		catch (SOAPFaultException sfe) {
			throw new RuntimeException(sfe.getMessage(), sfe);
		}
		return insertGroupAudit(groupAuditData, systemOverride, onBehalfOf, "");
	}

	public long insertGroupAudit(GroupAuditData groupAuditData, boolean systemOverride, String onBehalfOf, String appId) {
		List<Document> request = new ArrayList();
		try {
			JAXBContext propJaxbContext = JAXBContext.newInstance("com.fedex.enterprise.security.group.audits");
			Marshaller propMarshaller = propJaxbContext.createMarshaller();
			GroupAudit cdsGroupAudit = new GroupAudit();
			cdsGroupAudit.setChangedBy(groupAuditData.getChangedBy());
			GregorianCalendar c = new GregorianCalendar();
			XMLGregorianCalendar changeCalendar = DatatypeFactory.newInstance().newXMLGregorianCalendar(c);
			cdsGroupAudit.setDateChanged(changeCalendar);
			cdsGroupAudit.setEventDesc(groupAuditData.getEventDesc());
			cdsGroupAudit.setEventType(groupAuditData.getEventType());
			cdsGroupAudit.setGroupName(groupAuditData.getGroupName());
			cdsGroupAudit.setNewGroupFilter(groupAuditData.getNewGroupFilter());
			cdsGroupAudit.setNewGroupStaticMembers(groupAuditData.getNewGroupStaticMembers());
			cdsGroupAudit.setOldGroupFilter(groupAuditData.getOldGroupFilter());
			cdsGroupAudit.setOldGroupStaticMembers(groupAuditData.getOldGroupStaticMembers());
			cdsGroupAudit.setMajorVersion(getStanzaDescMajorVer());
			cdsGroupAudit.setMinorVersion(getStanzaDescMinorVer());
			Document doc = BuildDocument();
			propMarshaller.marshal(cdsGroupAudit, doc);
			request.add(doc);
			List<Long> keys = cdsClient.insert(request, null, systemOverride);
			groupAuditData.setDocId(keys.get(0).longValue());
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
		return groupAuditData.getDocId();
	}

	public List<GroupAuditData> getGroupAuditsForGroupName(String groupName, Bookmark bookmarkId) {
		List<GroupAuditData> response = new ArrayList();
		String bookmark = "";
		long totalDocCount = 0L;
		if (groupName == null) {
			return null;
		}
		if (bookmarkId == null) {
			bookmarkId = new Bookmark();
			bookmarkId.setBookmark("5120135");
		}
		ObjectFactory of = new ObjectFactory();
		StanzaIdType stanzaId = of.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("groupAudit");
		StanzaIdType indexStanzaId = of.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("groupAudit");
		List<IndexElementType> indexElements = new ArrayList();
		IndexElementType indexElement = new IndexElementType();
		indexElement.setXpath("/groupAudit/@GroupName");
		indexElement.setComparison("equals");
		indexElement.setValue(groupName);
		indexElements.add(indexElement);
		Unmarshaller unmarshaller;
		do {
			IndexQueryResponse indexResponse = cdsClient.indexQuery(indexElements, stanzaId, indexStanzaId, bookmark);
			List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
			JAXBContext propertiesStanzaContext = null;
			unmarshaller = null;
			try {
				propertiesStanzaContext = JAXBContext.newInstance(GroupAudit.class);
				unmarshaller = propertiesStanzaContext.createUnmarshaller();
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in getGroupAuditsForGroupName CdsSecurityGroupAudit create unmarshaller"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
				for (Iterator i$ = queryItem.getKeyedStanzas().iterator(); i$.hasNext(); ) {
					KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
					totalDocCount += 1L;
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						GroupAudit groupAudit = null;
						try {
							groupAudit = (GroupAudit)unmarshaller.unmarshal(docElement);
							GroupAuditData groupAuditData = new GroupAuditData();
							groupAuditData.setChangedBy(groupAudit.getChangedBy());
							groupAuditData.setDateChanged(groupAudit.getDateChanged().toGregorianCalendar().getTime());
							groupAuditData.setDocId(keyedStanzas.getKey());
							groupAuditData.setEventDesc(groupAudit.getEventDesc());
							groupAuditData.setEventType(groupAudit.getEventType());
							groupAuditData.setGroupName(groupAudit.getGroupName());
							groupAuditData.setNewGroupFilter(groupAudit.getNewGroupFilter());
							groupAuditData.setNewGroupStaticMembers(groupAudit.getNewGroupStaticMembers());
							groupAuditData.setOldGroupFilter(groupAudit.getOldGroupFilter());
							groupAuditData.setOldGroupStaticMembers(groupAudit.getOldGroupStaticMembers());
							response.add(groupAuditData);
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("Caught General JAXBException in getGroupAuditsForGroupName"), e);
						}
					}
				}
				bookmark = queryItem.getPaging().getBookmark();
			}
		}
		while ((!"".equals(bookmark)) && (bookmarkId.getBookmark() == "5120135"));
		bookmarkId.setBookmark(bookmark);
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR GROUP AUDIT = " + totalDocCount));
		return response;
	}

	public List<GroupAuditData> getGroupAuditsForDateRange(String groupName, Calendar startDate, Calendar endDate, Bookmark bookmarkId) {
		List<GroupAuditData> response = new ArrayList();
		String bookmark = "";
		long totalDocCount = 0L;
		if ((startDate == null) || (endDate == null)) {
			return null;
		}
		if (bookmarkId == null) {
			bookmarkId = new Bookmark();
			bookmarkId.setBookmark("5120135");
		}
		ObjectFactory of = new ObjectFactory();
		StanzaIdType stanzaId = of.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("groupAudit");
		StanzaIdType indexStanzaId = of.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("groupAudit");
		List<IndexElementType> indexElements = new ArrayList();
		IndexElementType indexElement = new IndexElementType();
		indexElement.setXpath("/groupAudit/@GroupName");
		indexElement.setComparison("equals");
		indexElement.setValue(groupName);
		indexElements.add(indexElement);
		try {
			indexElement = new IndexElementType();
			indexElement.setXpath("/groupAudit/@DateChanged");
			indexElement.setComparison("between");
			indexElement.setValue(EscUtils.convertCalendarToXMLString(startDate));
			indexElement.setSecondaryValue(EscUtils.convertCalendarToXMLString(endDate));
			indexElements.add(indexElement);
		}
		catch (Exception e) {
		}
		Unmarshaller unmarshaller;
		do {
			IndexQueryResponse indexResponse = cdsClient.indexQuery(indexElements, stanzaId, indexStanzaId, bookmark);
			List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
			JAXBContext propertiesStanzaContext = null;
			unmarshaller = null;
			try {
				propertiesStanzaContext = JAXBContext.newInstance(GroupAudit.class);
				unmarshaller = propertiesStanzaContext.createUnmarshaller();
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in getGroupAuditsForDateRange create unmarshaller"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
				for (Iterator i$ = queryItem.getKeyedStanzas().iterator(); i$.hasNext(); ) {
					KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
					totalDocCount += 1L;
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						GroupAudit groupAudit = null;
						try {
							groupAudit = (GroupAudit)unmarshaller.unmarshal(docElement);
							GroupAuditData groupAuditData = new GroupAuditData();
							groupAuditData.setChangedBy(groupAudit.getChangedBy());
							groupAuditData.setDateChanged(groupAudit.getDateChanged().toGregorianCalendar().getTime());
							groupAuditData.setDocId(keyedStanzas.getKey());
							groupAuditData.setEventDesc(groupAudit.getEventDesc());
							groupAuditData.setEventType(groupAudit.getEventType());
							groupAuditData.setGroupName(groupAudit.getGroupName());
							groupAuditData.setNewGroupFilter(groupAudit.getNewGroupFilter());
							groupAuditData.setNewGroupStaticMembers(groupAudit.getNewGroupStaticMembers());
							groupAuditData.setOldGroupFilter(groupAudit.getOldGroupFilter());
							groupAuditData.setOldGroupStaticMembers(groupAudit.getOldGroupStaticMembers());
							response.add(groupAuditData);
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("Caught General JAXBException in CdsSecurityGroupAudit "), e);
						}
					}
				}
				bookmark = queryItem.getPaging().getBookmark();
			}
		}
		while ((!"".equals(bookmark)) && (bookmarkId.getBookmark() == "5120135"));
		bookmarkId.setBookmark(bookmark);
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR GROUP AUDIT = " + totalDocCount));
		return response;
	}

	public GroupAudit getGroupAudit(long docId) {
		if (docId == 0L) {
			return null;
		}
		return null;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\cds\CdsSecurityGroupAudit.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */