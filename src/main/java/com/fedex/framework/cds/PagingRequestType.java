package com.fedex.framework.cds;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "pagingRequestType")
public class PagingRequestType {
	@XmlAttribute(required = true)
	protected int resultsPerPage;
	@XmlAttribute
	protected Boolean returnResultsCount;
	@XmlAttribute
	protected String bookmark;
	@XmlAttribute
	protected OrderType order;

	public int getResultsPerPage() {
		return this.resultsPerPage;
	}

	public void setResultsPerPage(int value) {
		this.resultsPerPage = value;
	}

	public Boolean isReturnResultsCount() {
		return this.returnResultsCount;
	}

	public void setReturnResultsCount(Boolean value) {
		this.returnResultsCount = value;
	}

	public String getBookmark() {
		return this.bookmark;
	}

	public void setBookmark(String value) {
		this.bookmark = value;
	}

	public OrderType getOrder() {
		return this.order;
	}

	public void setOrder(OrderType value) {
		this.order = value;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\framework\cds\PagingRequestType.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */