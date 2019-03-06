package com.fedex.enterprise.security.cds.authZ;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "")
@XmlRootElement(name = "resource")
public class Resource {
	@XmlAttribute(name = "ApplicationId", required = true)
	protected long applicationId;
	@XmlAttribute(name = "ResourceName", required = true)
	protected String resourceName;
	@XmlAttribute(name = "ResourceDesc", required = true)
	protected String resourceDesc;
	@XmlAttribute(name = "RootFlg", required = true)
	protected String rootFlg;
	@XmlAttribute(required = true)
	protected String domain;
	@XmlAttribute(required = true)
	protected int majorVersion;
	@XmlAttribute(required = true)
	protected int minorVersion;

	public long getApplicationId() {
		return this.applicationId;
	}

	public void setApplicationId(long value) {
		this.applicationId = value;
	}

	public String getResourceName() {
		return this.resourceName;
	}

	public void setResourceName(String value) {
		this.resourceName = value;
	}

	public String getResourceDesc() {
		return this.resourceDesc;
	}

	public void setResourceDesc(String value) {
		this.resourceDesc = value;
	}

	public String getRootFlg() {
		return this.rootFlg;
	}

	public void setRootFlg(String value) {
		this.rootFlg = value;
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
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\cds\authZ\Resource.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */