package com.fedex.framework.cds;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "pagingResponseType")
public class PagingResponseType {
	@XmlAttribute(required = true)
	protected int resultsPerPage;
	@XmlAttribute
	protected Integer resultsCount;
	@XmlAttribute(required = true)
	protected String bookmark;
	@XmlAttribute
	protected OrderType order;

	public int getResultsPerPage() {
		return this.resultsPerPage;
	}

	public void setResultsPerPage(int value) {
		this.resultsPerPage = value;
	}

	public Integer getResultsCount() {
		return this.resultsCount;
	}

	public void setResultsCount(Integer value) {
		this.resultsCount = value;
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
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\framework\cds\PagingResponseType.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */