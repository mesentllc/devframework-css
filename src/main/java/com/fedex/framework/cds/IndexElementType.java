package com.fedex.framework.cds;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import java.util.ArrayList;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "indexElementType", propOrder = {"xpath", "comparison", "value", "secondaryValue", "additionalValues"})
public class IndexElementType {
	@XmlElement(required = true)
	protected String xpath;
	@XmlElement(required = true)
	protected String comparison;
	protected String value;
	protected String secondaryValue;
	protected List<String> additionalValues;
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

	public String getComparison() {
		return this.comparison;
	}

	public void setComparison(String value) {
		this.comparison = value;
	}

	public String getValue() {
		return this.value;
	}

	public void setValue(String value) {
		this.value = value;
	}

	public String getSecondaryValue() {
		return this.secondaryValue;
	}

	public void setSecondaryValue(String value) {
		this.secondaryValue = value;
	}

	public List<String> getAdditionalValues() {
		if (this.additionalValues == null) {
			this.additionalValues = new ArrayList();
		}
		return this.additionalValues;
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
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\framework\cds\IndexElementType.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */