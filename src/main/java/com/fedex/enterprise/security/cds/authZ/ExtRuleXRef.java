package com.fedex.enterprise.security.cds.authZ;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "")
@XmlRootElement(name = "extRuleXRef")
public class ExtRuleXRef {
	@XmlAttribute(name = "RuleDocId", required = true)
	protected long ruleDocId;
	@XmlAttribute(name = "ExtRuleDocId", required = true)
	protected long extRuleDocId;
	@XmlAttribute(name = "ApplicationId", required = true)
	protected long applicationId;
	@XmlAttribute(required = true)
	protected String domain;
	@XmlAttribute(required = true)
	protected int majorVersion;
	@XmlAttribute(required = true)
	protected int minorVersion;

	public long getRuleDocId() {
		return this.ruleDocId;
	}

	public void setRuleDocId(long value) {
		this.ruleDocId = value;
	}

	public long getExtRuleDocId() {
		return this.extRuleDocId;
	}

	public void setExtRuleDocId(long value) {
		this.extRuleDocId = value;
	}

	public long getApplicationId() {
		return this.applicationId;
	}

	public void setApplicationId(long value) {
		this.applicationId = value;
	}

	public String getDomain() {
		if (this.domain == null) {
			return "authZ";
		}
		return this.domain;
	}

	public void setDomain(String value) {
		this.domain = value;
	}

	public int getMajorVersion() {
		return this.majorVersion;
	}

	public void setMajorVersion(int value) {
		this.majorVersion = value;
	}

	public int getMinorVersion() {
		return this.minorVersion;
	}

	public void setMinorVersion(int value) {
		this.minorVersion = value;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\cds\authZ\ExtRuleXRef.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */