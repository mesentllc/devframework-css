package com.fedex.cds;

import com.fedex.enterprise.security.cds.authZ.AuditRecord;
import com.fedex.enterprise.security.utils.AuditRecordData;
import com.fedex.framework.cds.IndexElementType;
import com.fedex.framework.cds.IndexQueryResponse;
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
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

public class CdsSecurityAuditReport
		extends CdsSecurityBase {
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(CdsSecurityAuditReport.class);

	public static long Insert(AuditRecordData auditRecordData) {
		return Insert(auditRecordData, false);
	}

	public static long Insert(AuditRecordData auditRecordData, boolean systemOverride) {
		List<Long> keys = null;
		List<Document> request = new ArrayList();
		try {
			com.fedex.enterprise.security.cds.authZ.ObjectFactory securityObjectFactory = new com.fedex.enterprise.security.cds.authZ.ObjectFactory();
			JAXBContext propJaxbContext = JAXBContext.newInstance("com.fedex.enterprise.security.cds.authZ");
			Marshaller propMarshaller = propJaxbContext.createMarshaller();
			AuditRecord auditRecord = securityObjectFactory.createAuditRecord();
			auditRecord.setDomain("authZ");
			auditRecord.setMajorVersion(STANZA_DESC_MAJOR_VER);
			auditRecord.setMinorVersion(STANZA_DESC_MINOR_VER);
			auditRecord.setAppOrRealm(auditRecordData.getAppOrRealm());
			auditRecord.setChangedBy(auditRecordData.getUpdateBy());
			String desc = auditRecordData.getEventDesc();
			if (desc.length() > 4096) {
				desc = desc.substring(0, 4095);
			}
			auditRecord.setEventDesc(desc);
			auditRecord.setEventTmstp(getStaticDateTime());
			auditRecord.setEventType(auditRecordData.getEventTypeCd());
			auditRecord.setImpactedStanza(auditRecordData.getStanzaNm());
			auditRecord.setDocumentId(Long.parseLong(auditRecordData.getDocKey()));
			Document doc = BuildDocument();
			propMarshaller.marshal(auditRecord, doc);
			request.add(doc);
			logger.warn(new FedExLogEntry("Audit: " + auditRecordData.getEventDesc()));
			logger.info(new FedExLogEntry("Inserting AuditRecord: " + auditRecord));
			keys = cdsClient.insert(request, null, systemOverride);
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

	public static long Insert(AuditRecord auditRecord, boolean systemOverride) {
		List<Document> request = new ArrayList();
		try {
			JAXBContext propJaxbContext = JAXBContext.newInstance("com.fedex.enterprise.security.cds.authZ");
			Marshaller propMarshaller = propJaxbContext.createMarshaller();
			Document doc = BuildDocument();
			propMarshaller.marshal(auditRecord, doc);
			request.add(doc);
			logger.info(new FedExLogEntry("Inserting AuditRecord: " + auditRecord));
			cdsClient.insert(request, null, systemOverride);
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
		return 0L;
	}

	public static void Delete(Long documentKey) {
		Delete(documentKey, false);
	}

	public static void Delete(Long documentKey, boolean systemOverride) {
		try {
			Delete(documentKey, "auditRecord", null, systemOverride);
		}
		catch (SoapFaultClientException sfx) {
			throw sfx;
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Caught general Exception ex: " + e.toString()));
			throw new RuntimeException(e);
		}
	}

	public static List<AuditRecordData> Retrieve(String appOrRealm, Calendar startDate, Calendar endDate, Bookmark bookmarkId) {
		if (bookmarkId == null) {
			bookmarkId = new Bookmark();
			bookmarkId.setBookmark("5120135");
		}
		String bookmark = "";
		List<AuditRecordData> response = new ArrayList();
		int totalDocCount = 0;
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		StanzaIdType stanzaId = of.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("auditRecord");
		StanzaIdType indexStanzaId = of.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("auditRecord");
		Unmarshaller unmarshaller;
		do {
			IndexQueryResponse indexResponse = cdsClient.indexQuery(BuildIndexQuery(appOrRealm, startDate, endDate), stanzaId, indexStanzaId, bookmark);
			List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
			JAXBContext auditRecordStanzaContext = null;
			unmarshaller = null;
			try {
				auditRecordStanzaContext = JAXBContext.newInstance(AuditRecord.class);
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Error in the Retrieve new instance"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			try {
				unmarshaller = auditRecordStanzaContext.createUnmarshaller();
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Error in the Retrieve create unmarshaller"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
				for (Iterator i$ = queryItem.getKeyedStanzas().iterator(); i$.hasNext(); ) {
					KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
					totalDocCount++;
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						AuditRecord auditRecord = null;
						try {
							auditRecord = (AuditRecord)unmarshaller.unmarshal(docElement);
							AuditRecordData auditRecordData = new AuditRecordData();
							auditRecordData.setAppOrRealm(auditRecord.getAppOrRealm());
							auditRecordData.setUpdateBy(auditRecord.getChangedBy());
							auditRecordData.setEventDesc(auditRecord.getEventDesc());
							auditRecordData.setOccurredTm(convertXMLtoTmstp(auditRecord.getEventTmstp()));
							auditRecordData.setEventTypeCd(AuditRecordData.ACTION.valueOf(auditRecord.getEventType()));
							auditRecordData.setStanzaNm(auditRecord.getImpactedStanza());
							auditRecordData.setDocKey(Long.toString(auditRecord.getDocumentId()));
							auditRecordData.setDocId(keyedStanzas.getKey());
							response.add(auditRecordData);
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("Error in the Retrieve unmarshal"), e);
						}
						continue;
					}
				}
				bookmark = queryItem.getPaging().getBookmark();
			}
		}
		while (!"".equals(bookmark));
		bookmarkId.setBookmark(bookmark);
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR AUDIT RECORD = " + totalDocCount));
		return response;
	}

	private static List<IndexElementType> BuildIndexQuery(String appOrRealm, Calendar startDate, Calendar endDate) {
		logger.info(new FedExLogEntry("Asking for audit records for app " + appOrRealm + " between " + new Date(startDate.getTimeInMillis()).toString() + " and " + new Date(endDate.getTimeInMillis()).toString()));
		List<IndexElementType> indexElements = new ArrayList();
		IndexElementType ie1 = new IndexElementType();
		ie1.setXpath("/auditRecord/@AppOrRealm");
		ie1.setComparison("equals");
		ie1.setValue(appOrRealm);
		indexElements.add(ie1);
		IndexElementType ie2 = new IndexElementType();
		ie2.setXpath("/auditRecord/@EventTmstp");
		ie2.setComparison("between");
		ie2.setValue(convertCalendarToXMLString(startDate));
		ie2.setSecondaryValue(convertCalendarToXMLString(endDate));
		indexElements.add(ie2);
		return indexElements;
	}

	private static String convertCalendarToXMLString(Calendar c) {
		DatatypeFactory dataFactory = null;
		XMLGregorianCalendar cal = null;
		try {
			dataFactory = DatatypeFactory.newInstance();
			cal = dataFactory.newXMLGregorianCalendar();
			cal.setYear(c.get(1));
			cal.setMonth(c.get(2) + 1);
			cal.setDay(c.get(5));
			cal.setHour(c.get(11));
			cal.setMinute(c.get(12));
			cal.setSecond(c.get(13));
			cal.setMillisecond(c.get(14));
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Unable to get the datatype factory to convert dates for the : " + e));
		}
		logger.info(new FedExLogEntry("Converted Calendar to XML String: " + cal.toString()));
		return cal.toString();
	}

	public static XMLGregorianCalendar getStaticDateTime() {
		DatatypeFactory dataFactory = null;
		XMLGregorianCalendar cal = null;
		try {
			dataFactory = DatatypeFactory.newInstance();
			cal = dataFactory.newXMLGregorianCalendar();
			Calendar c = Calendar.getInstance();
			cal.setYear(c.get(1));
			cal.setMonth(c.get(2) + 1);
			cal.setDay(c.get(5));
			cal.setHour(c.get(11));
			cal.setMinute(c.get(12));
			cal.setSecond(c.get(13));
			cal.setMillisecond(c.get(14));
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Unable to get the datatype factory to create dates for the : " + e));
		}
		return cal;
	}

	private static Timestamp convertXMLtoTmstp(XMLGregorianCalendar cal) {
		return new Timestamp(cal.toGregorianCalendar().getTimeInMillis());
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\cds\CdsSecurityAuditReport.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */