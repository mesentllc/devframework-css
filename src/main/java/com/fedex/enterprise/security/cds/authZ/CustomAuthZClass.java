package com.fedex.enterprise.security.cds.authZ;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "")
@XmlRootElement(name = "customAuthZClass")
public class CustomAuthZClass {
	@XmlAttribute(name = "CustomAuthZClassName", required = true)
	protected String customAuthZClassName;
	@XmlAttribute(name = "CustomAuthZClassDesc", required = true)
	protected String customAuthZClassDesc;
	@XmlAttribute(name = "ApplicationId", required = true)
	protected long applicationId;
	@XmlAttribute(required = true)
	protected String domain;
	@XmlAttribute(required = true)
	protected int majorVersion;
	@XmlAttribute(required = true)
	protected int minorVersion;

	public String getCustomAuthZClassName() {
		return this.customAuthZClassName;
	}

	public void setCustomAuthZClassName(String value) {
		this.customAuthZClassName = value;
	}

	public String getCustomAuthZClassDesc() {
		return this.customAuthZClassDesc;
	}

	public void setCustomAuthZClassDesc(String value) {
		this.customAuthZClassDesc = value;
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
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\cds\authZ\CustomAuthZClass.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */