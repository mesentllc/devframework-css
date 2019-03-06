package com.fedex.framework.cds;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {"insertResponse", "modifyResponse", "addResponse", "deleteResponse", "keyQueryResponse", "indexQueryResponse", "enrichedQueryResponse", "enrichedUpdateResponse"})
@XmlRootElement(name = "compositeResponse")
public class CompositeResponse {
	@XmlElement(namespace = "http://www.fedex.com/xmlns/cds2")
	protected InsertResponse insertResponse;
	@XmlElement(namespace = "http://www.fedex.com/xmlns/cds2")
	protected ModifyResponse modifyResponse;
	@XmlElement(namespace = "http://www.fedex.com/xmlns/cds2")
	protected AddResponse addResponse;
	@XmlElement(namespace = "http://www.fedex.com/xmlns/cds2")
	protected DeleteResponse deleteResponse;
	@XmlElement(namespace = "http://www.fedex.com/xmlns/cds2")
	protected KeyQueryResponse keyQueryResponse;
	@XmlElement(namespace = "http://www.fedex.com/xmlns/cds2")
	protected IndexQueryResponse indexQueryResponse;
	@XmlElement(namespace = "http://www.fedex.com/xmlns/cds2")
	protected EnrichedQueryResponse enrichedQueryResponse;
	@XmlElement(namespace = "http://www.fedex.com/xmlns/cds2")
	protected EnrichedUpdateResponse enrichedUpdateResponse;

	public InsertResponse getInsertResponse() {
		return this.insertResponse;
	}

	public void setInsertResponse(InsertResponse value) {
		this.insertResponse = value;
	}

	public ModifyResponse getModifyResponse() {
		return this.modifyResponse;
	}

	public void setModifyResponse(ModifyResponse value) {
		this.modifyResponse = value;
	}

	public AddResponse getAddResponse() {
		return this.addResponse;
	}

	public void setAddResponse(AddResponse value) {
		this.addResponse = value;
	}

	public DeleteResponse getDeleteResponse() {
		return this.deleteResponse;
	}

	public void setDeleteResponse(DeleteResponse value) {
		this.deleteResponse = value;
	}

	public KeyQueryResponse getKeyQueryResponse() {
		return this.keyQueryResponse;
	}

	public void setKeyQueryResponse(KeyQueryResponse value) {
		this.keyQueryResponse = value;
	}

	public IndexQueryResponse getIndexQueryResponse() {
		return this.indexQueryResponse;
	}

	public void setIndexQueryResponse(IndexQueryResponse value) {
		this.indexQueryResponse = value;
	}

	public EnrichedQueryResponse getEnrichedQueryResponse() {
		return this.enrichedQueryResponse;
	}

	public void setEnrichedQueryResponse(EnrichedQueryResponse value) {
		this.enrichedQueryResponse = value;
	}

	public EnrichedUpdateResponse getEnrichedUpdateResponse() {
		return this.enrichedUpdateResponse;
	}

	public void setEnrichedUpdateResponse(EnrichedUpdateResponse value) {
		this.enrichedUpdateResponse = value;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\framework\cds\CompositeResponse.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */