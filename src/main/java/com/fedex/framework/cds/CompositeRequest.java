package com.fedex.framework.cds;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {"insertRequest", "modifyRequest", "addRequest", "deleteRequest", "keyQueryRequest", "indexQueryRequest", "enrichedQueryRequest", "enrichedUpdateRequest"})
@XmlRootElement(name = "compositeRequest")
public class CompositeRequest {
	@XmlElement(namespace = "http://www.fedex.com/xmlns/cds2")
	protected InsertRequest insertRequest;
	@XmlElement(namespace = "http://www.fedex.com/xmlns/cds2")
	protected ModifyRequest modifyRequest;
	@XmlElement(namespace = "http://www.fedex.com/xmlns/cds2")
	protected AddRequest addRequest;
	@XmlElement(namespace = "http://www.fedex.com/xmlns/cds2")
	protected DeleteRequest deleteRequest;
	@XmlElement(namespace = "http://www.fedex.com/xmlns/cds2")
	protected KeyQueryRequest keyQueryRequest;
	@XmlElement(namespace = "http://www.fedex.com/xmlns/cds2")
	protected IndexQueryRequest indexQueryRequest;
	@XmlElement(namespace = "http://www.fedex.com/xmlns/cds2")
	protected EnrichedQueryRequest enrichedQueryRequest;
	@XmlElement(namespace = "http://www.fedex.com/xmlns/cds2")
	protected EnrichedUpdateRequest enrichedUpdateRequest;

	public InsertRequest getInsertRequest() {
		return this.insertRequest;
	}

	public void setInsertRequest(InsertRequest value) {
		this.insertRequest = value;
	}

	public ModifyRequest getModifyRequest() {
		return this.modifyRequest;
	}

	public void setModifyRequest(ModifyRequest value) {
		this.modifyRequest = value;
	}

	public AddRequest getAddRequest() {
		return this.addRequest;
	}

	public void setAddRequest(AddRequest value) {
		this.addRequest = value;
	}

	public DeleteRequest getDeleteRequest() {
		return this.deleteRequest;
	}

	public void setDeleteRequest(DeleteRequest value) {
		this.deleteRequest = value;
	}

	public KeyQueryRequest getKeyQueryRequest() {
		return this.keyQueryRequest;
	}

	public void setKeyQueryRequest(KeyQueryRequest value) {
		this.keyQueryRequest = value;
	}

	public IndexQueryRequest getIndexQueryRequest() {
		return this.indexQueryRequest;
	}

	public void setIndexQueryRequest(IndexQueryRequest value) {
		this.indexQueryRequest = value;
	}

	public EnrichedQueryRequest getEnrichedQueryRequest() {
		return this.enrichedQueryRequest;
	}

	public void setEnrichedQueryRequest(EnrichedQueryRequest value) {
		this.enrichedQueryRequest = value;
	}

	public EnrichedUpdateRequest getEnrichedUpdateRequest() {
		return this.enrichedUpdateRequest;
	}

	public void setEnrichedUpdateRequest(EnrichedUpdateRequest value) {
		this.enrichedUpdateRequest = value;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\framework\cds\CompositeRequest.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */