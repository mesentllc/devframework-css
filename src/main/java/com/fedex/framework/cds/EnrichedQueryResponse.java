package com.fedex.framework.cds;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAnyElement;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import java.util.ArrayList;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {"domain", "name", "any"})
@XmlRootElement(name = "enrichedQueryResponse")
public class EnrichedQueryResponse {
	@XmlElement(required = true)
	protected String domain;
	@XmlElement(required = true)
	protected String name;
	@XmlAnyElement(lax = true)
	protected List<Object> any;

	public String getDomain() {
		return this.domain;
	}

	public void setDomain(String value) {
		this.domain = value;
	}

	public String getName() {
		return this.name;
	}

	public void setName(String value) {
		this.name = value;
	}

	public List<Object> getAny() {
		if (this.any == null) {
			this.any = new ArrayList();
		}
		return this.any;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\framework\cds\EnrichedQueryResponse.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */