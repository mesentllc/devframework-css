package com.fedex.enterprise.security.cds.authZ;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "")
@XmlRootElement(name = "groupOwner")
public class GroupOwner {
	@XmlAttribute(name = "RoleDocId", required = true)
	protected long roleDocId;
	@XmlAttribute(name = "GroupName", required = true)
	protected String groupName;
	@XmlAttribute(required = true)
	protected String domain;
	@XmlAttribute(required = true)
	protected int majorVersion;
	@XmlAttribute(required = true)
	protected int minorVersion;

	public long getRoleDocId() {
		return this.roleDocId;
	}

	public void setRoleDocId(long value) {
		this.roleDocId = value;
	}

	public String getGroupName() {
		return this.groupName;
	}

	public void setGroupName(String value) {
		this.groupName = value;
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
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\cds\authZ\GroupOwner.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */