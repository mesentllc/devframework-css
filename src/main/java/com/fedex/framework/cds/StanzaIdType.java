package com.fedex.framework.cds;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "stanzaIdType", propOrder = {"domain", "name", "version"})
public class StanzaIdType {
	@XmlElement(required = true)
	protected String domain;
	@XmlElement(required = true)
	protected String name;
	protected String version;

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

	public String getVersion() {
		return this.version;
	}

	public void setVersion(String value) {
		this.version = value;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\framework\cds\StanzaIdType.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */