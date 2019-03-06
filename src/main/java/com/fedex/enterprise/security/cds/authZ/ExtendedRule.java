package com.fedex.enterprise.security.cds.authZ;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "")
@XmlRootElement(name = "extendedRule")
public class ExtendedRule {
	@XmlAttribute(name = "ExtendedRuleKey", required = true)
	protected String extendedRuleKey;
	@XmlAttribute(name = "ExtendedRuleOperator", required = true)
	protected String extendedRuleOperator;
	@XmlAttribute(name = "ExtendedRuleValue", required = true)
	protected String extendedRuleValue;
	@XmlAttribute(name = "ExtendedRuleValueType", required = true)
	protected String extendedRuleValueType;
	@XmlAttribute(name = "ApplicationId", required = true)
	protected long applicationId;
	@XmlAttribute(required = true)
	protected String domain;
	@XmlAttribute(required = true)
	protected int majorVersion;
	@XmlAttribute(required = true)
	protected int minorVersion;

	public String getExtendedRuleKey() {
		return this.extendedRuleKey;
	}

	public void setExtendedRuleKey(String value) {
		this.extendedRuleKey = value;
	}

	public String getExtendedRuleOperator() {
		return this.extendedRuleOperator;
	}

	public void setExtendedRuleOperator(String value) {
		this.extendedRuleOperator = value;
	}

	public String getExtendedRuleValue() {
		return this.extendedRuleValue;
	}

	public void setExtendedRuleValue(String value) {
		this.extendedRuleValue = value;
	}

	public String getExtendedRuleValueType() {
		return this.extendedRuleValueType;
	}

	public void setExtendedRuleValueType(String value) {
		this.extendedRuleValueType = value;
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
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\cds\authZ\ExtendedRule.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */