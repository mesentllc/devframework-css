package com.fedex.framework.cds;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "sortElementType", propOrder = {"xpath"})
public class SortElementType {
	@XmlElement(required = true)
	protected String xpath;
	@XmlAttribute
	protected SortType sort;
	@XmlAttribute
	protected Integer order;

	public String getXpath() {
		return this.xpath;
	}

	public void setXpath(String value) {
		this.xpath = value;
	}

	public SortType getSort() {
		return this.sort;
	}

	public void setSort(SortType value) {
		this.sort = value;
	}

	public Integer getOrder() {
		return this.order;
	}

	public void setOrder(Integer value) {
		this.order = value;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\framework\cds\SortElementType.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */