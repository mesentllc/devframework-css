package com.fedex.cds;

import com.fedex.ea.framework.securityapi.dao.esc.EscDaoException;
import com.fedex.ea.framework.securityapi.dao.esc.cds.mapper.CdsMapper;
import com.fedex.ea.framework.securityapi.dao.esc.cds.mapper.CdsMapperFactory;
import com.fedex.enterprise.security.utils.SecurityDataBaseClass;
import com.fedex.framework.cds.CompositeRequest;
import com.fedex.framework.cds.CompositeResponse;
import com.fedex.framework.cds.DeleteRequest;
import com.fedex.framework.cds.DeleteResponse;
import com.fedex.framework.cds.EnrichedQueryRequest;
import com.fedex.framework.cds.EnrichedQueryResponse;
import com.fedex.framework.cds.IndexElementType;
import com.fedex.framework.cds.IndexQueryRequest;
import com.fedex.framework.cds.IndexQueryResponse;
import com.fedex.framework.cds.InsertRequest;
import com.fedex.framework.cds.InsertResponse;
import com.fedex.framework.cds.KeyQueryRequest;
import com.fedex.framework.cds.KeyQueryResponse;
import com.fedex.framework.cds.KeyedStanzasType;
import com.fedex.framework.cds.ModifyRequest;
import com.fedex.framework.cds.ObjectFactory;
import com.fedex.framework.cds.PagingRequestType;
import com.fedex.framework.cds.PagingResponseType;
import com.fedex.framework.cds.SequenceRequest;
import com.fedex.framework.cds.SequenceResponse;
import com.fedex.framework.cds.StanzaIdType;
import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLoggerInterface;
import org.springframework.ws.client.core.WebServiceTemplate;
import org.springframework.ws.soap.SoapFaultDetail;
import org.springframework.ws.soap.SoapFaultDetailElement;
import org.springframework.ws.soap.client.SoapFaultClientException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.bind.JAXBException;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.transform.dom.DOMResult;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class CdsClient {
	private static final FedExLoggerInterface LOGGER = com.fedex.framework.logging.FedExLogger.getLogger(CdsClient.class);
	private final CdsMapperFactory mapperFactory = new com.fedex.ea.framework.securityapi.dao.esc.cds.mapper.CdsMapperCacheFactory();
	private WebServiceTemplate webServiceTemplate;
	private static ObjectFactory objectFactory;
	private static final ObjectFactory OBJECT_FACTORY = new ObjectFactory();
	private static final int ITEMS_PER_REQUEST = 100;
	private static final int MAX_KEYS_FOR_CDS_REQUEST = 500;

	public enum QUERY_COMPARE {
		equals,
		like,
		between;

		QUERY_COMPARE() {
		}
	}

	public WebServiceTemplate getWebServiceTemplate() {
		return this.webServiceTemplate;
	}

	public void setWebServiceTemplate(WebServiceTemplate webServiceTemplate) {
		this.webServiceTemplate = webServiceTemplate;
	}

	public static ObjectFactory GetObjectFactoryInstance() {
		if (objectFactory == null) {
			objectFactory = new ObjectFactory();
		}
		return objectFactory;
	}

	public CdsClient() {
		objectFactory = new ObjectFactory();
		LOGGER.debug(new FedExLogEntry("Initialized the CdsClient()"));
	}

	public KeyQueryResponse keyQuery(KeyQueryRequest request) {
		return (KeyQueryResponse)this.webServiceTemplate.marshalSendAndReceive(request);
	}

	public EnrichedQueryResponse enrichedQuery(EnrichedQueryRequest request) {
		return (EnrichedQueryResponse)this.webServiceTemplate.marshalSendAndReceive(request);
	}

	public KeyQueryResponse systemKeyQuery(KeyQueryRequest request) {
		return (KeyQueryResponse)this.webServiceTemplate.marshalSendAndReceive(request);
	}

	public List<SecurityDataBaseClass> keyQuery(List<Long> keys, String domain, CdsSecurityBase.STANZAS name, boolean mapObjects)
			throws EscDaoException {
		KeyQueryRequest.StanzaId stanza = createKeyQueryStanzaId(domain, name);
		return keyQuery(keys, new ArrayList(Arrays.asList(stanza)), mapObjects);
	}

	public List<SecurityDataBaseClass> keyQuery(List<Long> keys, List<KeyQueryRequest.StanzaId> stanzaId, boolean mapObjects) throws EscDaoException {
		if (keys.isEmpty()) {
			LOGGER.always("Unable to query with an empty set of keys");
			return new ArrayList(0);
		}
		if (stanzaId.isEmpty()) {
			throw new EscDaoException("Unable to query with an empty set of stanzaId");
		}
		List<SecurityDataBaseClass> returnList = new ArrayList();
		List<Long> distinctKeys = new ArrayList(new java.util.HashSet(keys));
		Iterator<Long> keyIter = distinctKeys.iterator();
		do {
			List<String> listOfKeys = new ArrayList();
			for (int counter = 0; counter < 500; counter++) {
				if (keyIter.hasNext()) {
					long key = keyIter.next().longValue();
					if (key == 0L) {
						LOGGER.always("Attemting to query for a 0 key in stanza " + stanzaId.get(0).getName());
					}
					else {
						listOfKeys.add(Long.toString(key));
					}
				}
			}
			if (listOfKeys.isEmpty()) {
				LOGGER.always("Attemting a query with an empty set of keys");
			}
			else {
				KeyQueryRequest keyQueryRequest = new KeyQueryRequest();
				keyQueryRequest.getKey().addAll(listOfKeys);
				keyQueryRequest.getStanzaId().addAll(stanzaId);
				KeyQueryResponse response;
				try {
					response = (KeyQueryResponse)this.webServiceTemplate.marshalSendAndReceive(keyQueryRequest);
				}
				catch (SoapFaultClientException sfce) {
					logSoapException(sfce, keyQueryRequest);
					throw new EscDaoException("Unable to do an key query.  Please contact EA-FRAMEWORK team", sfce);
				}
				catch (RuntimeException exception) {
					throw new EscDaoException("Unable to do an key query.  Please contact EA-FRAMEWORK team", exception);
				}
				List<SecurityDataBaseClass> innerList = processKeyedStanzas(response.getKeyedStanzas(), mapObjects);
				if (listOfKeys.size() != innerList.size()) {
					LOGGER.always("Mismatch in object count returned in key query. Requested: " + keys.size() + ", returned: " + innerList.size() + " for " + stanzaId.get(0).getName());
				}
				returnList.addAll(innerList);
			}
		}
		while (keyIter.hasNext());
		return returnList;
	}

	public static KeyQueryRequest.StanzaId createKeyQueryStanzaId(String domain, CdsSecurityBase.STANZAS name) {
		KeyQueryRequest.StanzaId stanza = OBJECT_FACTORY.createKeyQueryRequestStanzaId();
		stanza.setDomain(domain);
		stanza.setName(name.toString());
		return stanza;
	}

	public List<SecurityDataBaseClass> indexQuery(String filterPath, QUERY_COMPARE filterCompare, String filterValue, String filterDomain, CdsSecurityBase.STANZAS filterStanza, String returnDomain, CdsSecurityBase.STANZAS returnStanza, boolean mapObjects)
			throws EscDaoException {
		IndexElementType indexElemenet = createIndexQueryItemIndexElemet(filterPath, filterCompare, filterValue, null);
		IndexQueryRequest.QueryItem.Index index = createIndexQueryItemIndex(filterDomain, filterStanza, new ArrayList(Arrays.asList(indexElemenet)));
		IndexQueryRequest.QueryItem queryItem = createIndexQueryItem(returnDomain, returnStanza, new ArrayList(Arrays.asList(index)));
		IndexQueryRequest indexQueryRequest = createIndexQuery(new ArrayList(Arrays.asList(queryItem)));
		return indexQuery(indexQueryRequest, mapObjects);
	}

	public List<SecurityDataBaseClass> indexQuery(String filterPath1, QUERY_COMPARE filterCompare1, String filterValue1, String filterPath2, QUERY_COMPARE filterCompare2, String filterValue2, String filterDomain, CdsSecurityBase.STANZAS filterStanza, String returnDomain, CdsSecurityBase.STANZAS returnStanza, boolean mapObjects)
			throws EscDaoException {
		IndexElementType indexElemenet1 = createIndexQueryItemIndexElemet(filterPath1, filterCompare1, filterValue1, null);
		IndexElementType indexElemenet2 = createIndexQueryItemIndexElemet(filterPath2, filterCompare2, filterValue2, null);
		IndexQueryRequest.QueryItem.Index index = createIndexQueryItemIndex(filterDomain, filterStanza, new ArrayList(Arrays.asList(indexElemenet1, indexElemenet2)));
		IndexQueryRequest.QueryItem queryItem = createIndexQueryItem(returnDomain, returnStanza, new ArrayList(Arrays.asList(index)));
		IndexQueryRequest indexQueryRequest = createIndexQuery(new ArrayList(Arrays.asList(queryItem)));
		return indexQuery(indexQueryRequest, mapObjects);
	}

	public List<SecurityDataBaseClass> indexQuery(IndexQueryRequest request, boolean mapObjects) throws EscDaoException {
		if ((request == null) || (request.getQueryItem() == null)) {
			throw new EscDaoException("Unable to perform index quey.  There is not a query item");
		}
		Map<Long, SecurityDataBaseClass> returnMap = new HashMap();
		IndexQueryRequest request1 = request;
		while (!request1.getQueryItem().isEmpty()) {
			IndexQueryResponse response = null;
			try {
				response = (IndexQueryResponse)this.webServiceTemplate.marshalSendAndReceive(request1);
			}
			catch (SoapFaultClientException sfce) {
				logSoapException(sfce, request1);
				throw new EscDaoException("Unable to do an index query.  Please contact EA-FRAMEWORK team", sfce);
			}
			catch (RuntimeException exception) {
				throw new EscDaoException("Unable to do an index query.  Please contact EA-FRAMEWORK team", exception);
			}
			if ((response != null) && (response.getQueryItem() != null) && (response.getQueryItem().size() != request1.getQueryItem().size())) {
				throw new EscDaoException("Size mismatch in index query size.  Please contact EA-FRAMEWORK team");
			}
			IndexQueryRequest request2 = new IndexQueryRequest();
			if ((response != null) && (response.getQueryItem() != null)) {
				List<IndexQueryResponse.QueryItem> queryItemList = response.getQueryItem();
				for (int indexQueryItemCnt = 0; indexQueryItemCnt < queryItemList.size(); indexQueryItemCnt++) {
					IndexQueryResponse.QueryItem responseQueryItem = queryItemList.get(indexQueryItemCnt);
					List<SecurityDataBaseClass> dataList = processKeyedStanzas(responseQueryItem.getKeyedStanzas(), mapObjects);
					for (SecurityDataBaseClass data : dataList) {
						if (!returnMap.containsKey(Long.valueOf(data.getDocId()))) {
							returnMap.put(Long.valueOf(data.getDocId()), data);
						}
					}
					PagingResponseType pagingResponse = responseQueryItem.getPaging();
					String bookmark = pagingResponse.getBookmark();
					if (!bookmark.isEmpty()) {
						IndexQueryRequest.QueryItem requestQueryItem = request1.getQueryItem().get(indexQueryItemCnt);
						PagingRequestType pagingRequest = OBJECT_FACTORY.createPagingRequestType();
						pagingRequest.setResultsPerPage(100);
						pagingRequest.setBookmark(bookmark);
						requestQueryItem.setPaging(pagingRequest);
						request2.getQueryItem().add(requestQueryItem);
					}
				}
			}
			request1 = request2;
		}
		return new ArrayList(returnMap.values());
	}

	public static IndexElementType createIndexQueryItemIndexElemet(String xpath, QUERY_COMPARE comparison, Long value) {
		return createIndexQueryItemIndexElemet(xpath, comparison, Long.toString(value.longValue()), null);
	}

	public static IndexElementType createIndexQueryItemIndexElemet(String xpath, QUERY_COMPARE comparison, String value, String secondaryValue) {
		IndexElementType indexElement = OBJECT_FACTORY.createIndexElementType();
		indexElement.setXpath(xpath);
		indexElement.setComparison(comparison.toString());
		indexElement.setValue(value);
		if (secondaryValue != null) {
			indexElement.setSecondaryValue(value);
		}
		return indexElement;
	}

	public static IndexQueryRequest.QueryItem.Index createIndexQueryItemIndex(String filterDomain, CdsSecurityBase.STANZAS filterName, List<IndexElementType> listItemElement) {
		IndexQueryRequest.QueryItem.Index index = OBJECT_FACTORY.createIndexQueryRequestQueryItemIndex();
		index.setStanzaId(createStanzaType(filterDomain, filterName.toString()));
		index.getIndexElement().addAll(listItemElement);
		return index;
	}

	public static IndexQueryRequest.QueryItem createIndexQueryItem(String filterPath, QUERY_COMPARE filterCompare, String filterValue, String filterDomain, CdsSecurityBase.STANZAS filterStanza, String returnDomain, CdsSecurityBase.STANZAS returnStanza)
			throws EscDaoException {
		IndexElementType indexElemenet = createIndexQueryItemIndexElemet(filterPath, filterCompare, filterValue, null);
		IndexQueryRequest.QueryItem.Index index = createIndexQueryItemIndex(filterDomain, filterStanza, new ArrayList(Arrays.asList(indexElemenet)));
		IndexQueryRequest.QueryItem queryItem = createIndexQueryItem(returnDomain, returnStanza, new ArrayList(Arrays.asList(index)));
		return queryItem;
	}

	public static IndexQueryRequest.QueryItem createIndexQueryItem(String returnDomain, CdsSecurityBase.STANZAS returnName, List<IndexQueryRequest.QueryItem.Index> listIndex) {
		IndexQueryRequest.QueryItem queryItem = OBJECT_FACTORY.createIndexQueryRequestQueryItem();
		queryItem.getIndex().addAll(listIndex);
		queryItem.getStanzaId().add(createStanzaType(returnDomain, returnName.toString()));
		return queryItem;
	}

	public static IndexQueryRequest createIndexQuery(List<IndexQueryRequest.QueryItem> listQueryItem) {
		IndexQueryRequest indexQueryRequest = OBJECT_FACTORY.createIndexQueryRequest();
		indexQueryRequest.getQueryItem().addAll(listQueryItem);
		return indexQueryRequest;
	}

	public static StanzaIdType createStanzaType(String domain, String name) {
		StanzaIdType stanza = OBJECT_FACTORY.createStanzaIdType();
		stanza.setDomain(domain);
		stanza.setName(name);
		return stanza;
	}

	protected void logSoapException(SoapFaultClientException sfce, Object request) {
		StringBuilder stringBuilder = new StringBuilder();
		try {
			SoapFaultDetail soapFaultDetail = sfce.getSoapFault().getFaultDetail();
			Iterator<SoapFaultDetailElement> soapIter = soapFaultDetail.getDetailEntries();
			while (soapIter.hasNext()) {
				SoapFaultDetailElement detailElementChild = soapIter.next();
				stringBuilder.append(((DOMResult)detailElementChild.getResult()).getNode().getTextContent()).append(", ");
			}
		}
		catch (Exception e2) {
			stringBuilder.append("Unable to get the SOAP details");
		}
		LOGGER.error("Unable to do an indexQuery.  SOAP errors: " + stringBuilder.toString());
	}

	protected List<SecurityDataBaseClass> processKeyedStanzas(List<KeyedStanzasType> keyedStanzasList, boolean mapObjects) throws EscDaoException {
		Map<Long, SecurityDataBaseClass> returnMap = new HashMap(keyedStanzasList.size());
		for (KeyedStanzasType keyedStanzas : keyedStanzasList) {
			long key = keyedStanzas.getKey();
			if (!returnMap.containsKey(Long.valueOf(key))) {
				List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
				for (KeyedStanzasType.Stanza stanza : stanzaList) {
					String stanzaName = stanza.getName();
					XMLGregorianCalendar xmlGregorianCalendar = stanza.getLastUpdate();
					if (stanzaName == null) {
						throw new EscDaoException("The CDS query returned an empty stanza name");
					}
					SecurityDataBaseClass cdsObject;
					if (mapObjects) {
						try {
							CdsMapper mapper = this.mapperFactory.createMapper(CdsSecurityBase.STANZAS.valueOf(stanzaName));
							cdsObject = mapper.unmarshal(stanza.getAny());
							if (!cdsObject.validate()) {
								LOGGER.always("Received invalid data from CDS: " + cdsObject.getValidationError() + cdsObject.toString());
							}
						}
						catch (JAXBException e) {
							throw new EscDaoException("Unable process data returned from CDS.  Please contact EA-FRAMEWORK team", e);
						}
					}
					else {
						cdsObject = com.fedex.ea.framework.securityapi.dao.esc.cds.CdsDataFactoy.createData(CdsSecurityBase.STANZAS.valueOf(stanzaName));
					}
					cdsObject.setDocId(key);
					cdsObject.setLastUpdated(xmlGregorianCalendar.toGregorianCalendar().getTime());
					returnMap.put(key, cdsObject);
				}
			}
		}
		return new ArrayList(returnMap.values());
	}

	public IndexQueryResponse indexQuery(List<IndexElementType> indexElements, StanzaIdType stanzaId, StanzaIdType indexStanzaId, String bookmark) {
		IndexQueryResponse queryResponse = new IndexQueryResponse();
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
		paging.setResultsPerPage(100);
		paging.setBookmark(bookmark);
		queryItem.setPaging(paging);
		queryItems.add(queryItem);
		IndexQueryResponse partialResponse = null;
		partialResponse = (IndexQueryResponse)this.webServiceTemplate.marshalSendAndReceive(request);
		if (partialResponse == null) {
			return null;
		}
		List<IndexQueryResponse.QueryItem> queryItemList = partialResponse.getQueryItem();
		queryResponse.getQueryItem().addAll(queryItemList);
		return queryResponse;
	}

	public IndexQueryResponse indexQueryMultiples(List<IndexQueryRequest.QueryItem> queryItems, String bookmark) {
		IndexQueryResponse queryResponse = new IndexQueryResponse();
		IndexQueryRequest request = objectFactory.createIndexQueryRequest();
		request.getQueryItem().addAll(queryItems);
		queryResponse = (IndexQueryResponse)this.webServiceTemplate.marshalSendAndReceive(request);
		return queryResponse;
	}

	public List<Long> insert(List<Document> docs, List<InsertRequest.InsertItem> auditRecords) {
		return insert(docs, auditRecords, false);
	}

	public List<Long> insert(List<Document> docs, List<InsertRequest.InsertItem> auditRecords, boolean systemOverride) {
		List<Long> listOfKeys = new ArrayList();
		InsertRequest request = new InsertRequest();
		for (Document currentDoc : docs) {
			InsertRequest.InsertItem insertItem = objectFactory.createInsertRequestInsertItem();
			insertItem.getAny().add(currentDoc.getDocumentElement());
			request.getInsertItem().add(insertItem);
		}
		if (auditRecords != null) {
			request.getInsertItem().addAll(auditRecords);
		}
		InsertResponse response = (InsertResponse)this.webServiceTemplate.marshalSendAndReceive(request);
		List<KeyedStanzasType> list = response.getInsertItem();
		LOGGER.debug(new FedExLogEntry(">>> Inserted " + list.size() + " total parent documents"));
		for (Iterator i$ = list.iterator(); i$.hasNext(); ) {
			KeyedStanzasType oneItem = (KeyedStanzasType)i$.next();
			for (KeyedStanzasType.Stanza stanza : oneItem.getStanza()) {
				LOGGER.debug(new FedExLogEntry(">>> Inserted Key=" + oneItem.getKey() + " in stanza " + stanza.getName()));
				if (!"auditRecord".equals(stanza.getName())) {
					listOfKeys.add(oneItem.getKey());
				}
			}
		}
		return listOfKeys;
	}

	public List<Long> insertAuditRecord(InsertRequest.InsertItem auditRecords) {
		InsertRequest request = new InsertRequest();
		List<Long> listOfKeys = new ArrayList();
		if (auditRecords != null) {
			request.getInsertItem().add(auditRecords);
		}
		InsertResponse response = (InsertResponse)this.webServiceTemplate.marshalSendAndReceive(request);
		List<KeyedStanzasType> list = response.getInsertItem();
		LOGGER.debug(new FedExLogEntry(">>> Inserted " + list.size() + " total parent documents"));
		for (Iterator i$ = list.iterator(); i$.hasNext(); ) {
			KeyedStanzasType oneItem = (KeyedStanzasType)i$.next();
			for (KeyedStanzasType.Stanza stanza : oneItem.getStanza()) {
				LOGGER.debug(new FedExLogEntry(">>> Inserted Key=" + oneItem.getKey() + " in stanza " + stanza.getName()));
				if (!"auditRecord".equals(stanza.getName())) {
					listOfKeys.add(oneItem.getKey());
				}
			}
		}
		return listOfKeys;
	}

	public void delete(List<Long> keys, String domainName, String stanzaName, List<InsertRequest.InsertItem> auditRecords) {
		delete(keys, domainName, stanzaName, auditRecords, false);
	}

	public void delete(List<Long> keys, String domainName, String stanzaName, List<InsertRequest.InsertItem> auditRecords, boolean systemOverride) {
		DeleteRequest request = objectFactory.createDeleteRequest();
		List<DeleteRequest.DeleteItem> deleteItems = new ArrayList();
		List<InsertRequest.InsertItem> auditItems = new ArrayList();
		Iterator<Long> it = keys.iterator();
		Iterator<InsertRequest.InsertItem> auditIterator = auditRecords.iterator();
		do {
			for (int count = 0; count < 100; count++) {
				if (it.hasNext()) {
					DeleteRequest.DeleteItem deleteItem = objectFactory.createDeleteRequestDeleteItem();
					deleteItem.getKey().add(Long.valueOf(it.next().longValue()));
					DeleteRequest.DeleteItem.StanzaId stanzaId = objectFactory.createDeleteRequestDeleteItemStanzaId();
					stanzaId.setDomain(domainName);
					stanzaId.setName(stanzaName);
					deleteItem.getStanzaId().add(stanzaId);
					deleteItems.add(deleteItem);
					if (auditIterator.hasNext()) {
						InsertRequest.InsertItem insertItem = auditIterator.next();
						auditItems.add(insertItem);
					}
				}
			}
			if (auditRecords != null) {
				CompositeRequest composite = new CompositeRequest();
				InsertRequest insert = new InsertRequest();
				insert.getInsertItem().addAll(auditItems);
				request.getDeleteItem().addAll(deleteItems);
				composite.setDeleteRequest(request);
				composite.setInsertRequest(insert);
				CompositeResponse compositeResponse = (CompositeResponse)this.webServiceTemplate.marshalSendAndReceive(composite);
				DeleteResponse response = compositeResponse.getDeleteResponse();
				List<KeyedStanzasType> keyedStanzas = response.getDeleteItem();
				for (KeyedStanzasType keyedStanza : keyedStanzas) {
					LOGGER.warn(new FedExLogEntry("Deleted Key: " + keyedStanza.getKey()));
				}
				LOGGER.warn(new FedExLogEntry("auditItems size: " + auditItems.size()));
				LOGGER.warn(new FedExLogEntry("deleteItems size: " + deleteItems.size()));
			}
			else {
				request.getDeleteItem().addAll(deleteItems);
				DeleteResponse response = (DeleteResponse)this.webServiceTemplate.marshalSendAndReceive(request);
				List<KeyedStanzasType> keyedStanzas = response.getDeleteItem();
				for (KeyedStanzasType keyedStanza : keyedStanzas) {
					LOGGER.warn(new FedExLogEntry("Deleted Key: " + keyedStanza.getKey()));
				}
				LOGGER.warn(new FedExLogEntry("auditItems size: " + auditItems.size()));
				LOGGER.warn(new FedExLogEntry("deleteItems size: " + deleteItems.size()));
			}
			deleteItems.clear();
			auditItems.clear();
			request.getDeleteItem().clear();
		}
		while (it.hasNext());
	}

	public void update(Map<String, String> xpathList, long docId, String domain, String stanza, InsertRequest.InsertItem auditRecord) {
		update(xpathList, docId, domain, stanza, auditRecord, false);
	}

	public void update(Map<String, String> xpathList, long docId, String domain, String stanza, InsertRequest.InsertItem auditRecord, boolean systemOverride) {
		ModifyRequest request = objectFactory.createModifyRequest();
		ModifyRequest.ModifyItem modifyItem = objectFactory.createModifyRequestModifyItem();
		StanzaIdType stanzaId = objectFactory.createStanzaIdType();
		stanzaId.setDomain(domain);
		stanzaId.setName(stanza);
		modifyItem.setStanzaId(stanzaId);
		ModifyRequest.ModifyItem.KeyAndLock myKey = objectFactory.createModifyRequestModifyItemKeyAndLock();
		myKey.setKey(docId);
		modifyItem.getKeyAndLock().add(myKey);
		Set<Map.Entry<String, String>> pathList = xpathList.entrySet();
		if (!pathList.isEmpty()) {
			Iterator<Map.Entry<String, String>> pathlistItr = pathList.iterator();
			while (pathlistItr.hasNext()) {
				Map.Entry<String, String> currentEntry = pathlistItr.next();
				ModifyRequest.ModifyItem.Action newAction = objectFactory.createModifyRequestModifyItemAction();
				ModifyRequest.ModifyItem.Action.Change change = new ModifyRequest.ModifyItem.Action.Change();
				change.setValue(currentEntry.getValue());
				change.setXpath(currentEntry.getKey());
				newAction.setChange(change);
				modifyItem.getAction().add(newAction);
			}
			request.getModifyItem().add(modifyItem);
			if (auditRecord != null) {
				InsertRequest insert = new InsertRequest();
				insert.getInsertItem().add(auditRecord);
				CompositeRequest composite = new CompositeRequest();
				composite.setModifyRequest(request);
				composite.setInsertRequest(insert);
				this.webServiceTemplate.marshalSendAndReceive(composite);
			}
			else {
				this.webServiceTemplate.marshalSendAndReceive(request);
			}
		}
	}

	public CompositeResponse update(String xpath, long docId, String domain, String stanza, InsertRequest.InsertItem auditRecord, boolean systemOverride, Element e) {
		ModifyRequest request = objectFactory.createModifyRequest();
		ModifyRequest.ModifyItem modifyItem = objectFactory.createModifyRequestModifyItem();
		StanzaIdType stanzaId = objectFactory.createStanzaIdType();
		stanzaId.setDomain(domain);
		stanzaId.setName(stanza);
		modifyItem.setStanzaId(stanzaId);
		ModifyRequest.ModifyItem.KeyAndLock myKey = objectFactory.createModifyRequestModifyItemKeyAndLock();
		myKey.setKey(docId);
		modifyItem.getKeyAndLock().add(myKey);
		ModifyRequest.ModifyItem.Action newAction = objectFactory.createModifyRequestModifyItemAction();
		ModifyRequest.ModifyItem.Action.Change change = new ModifyRequest.ModifyItem.Action.Change();
		change.setXpath(xpath);
		ModifyRequest.ModifyItem.Action.Change.XmlValue xmlValue = new ModifyRequest.ModifyItem.Action.Change.XmlValue();
		xmlValue.setAny(e);
		change.setXmlValue(xmlValue);
		newAction.setChange(change);
		modifyItem.getAction().add(newAction);
		request.getModifyItem().add(modifyItem);
		InsertRequest insert = new InsertRequest();
		insert.getInsertItem().add(auditRecord);
		CompositeRequest composite = new CompositeRequest();
		composite.setModifyRequest(request);
		composite.setInsertRequest(insert);
		CompositeResponse response = (CompositeResponse)this.webServiceTemplate.marshalSendAndReceive(composite);
		return response;
	}

	public SequenceResponse restrictionSequenceRequest(int blockSize) {
		SequenceResponse response = objectFactory.createSequenceResponse();
		SequenceRequest request = objectFactory.createSequenceRequest();
		request.setDomain("authZ");
		request.setSequenceName("restrictionSequence");
		request.setBlockSize(blockSize);
		response = (SequenceResponse)this.webServiceTemplate.marshalSendAndReceive(request);
		return response;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\cds\CdsClient.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */