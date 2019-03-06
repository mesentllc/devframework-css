package com.fedex.enterprise.security.cds.authZ;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "")
@XmlRootElement(name = "rule")
public class Rule {
	@XmlAttribute(name = "RoleDocId", required = true)
	protected long roleDocId;
	@XmlAttribute(name = "ResourceDocId", required = true)
	protected long resourceDocId;
	@XmlAttribute(name = "GrantDenyFlg", required = true)
	protected GrantDenyFlg grantDenyFlg;
	@XmlAttribute(name = "ApplicationId", required = true)
	protected long applicationId;
	@XmlAttribute(name = "CustAuthZDocId", required = true)
	protected long custAuthZDocId;
	@XmlAttribute(name = "ActionDocId", required = true)
	protected long actionDocId;
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

	public long getResourceDocId() {
		return this.resourceDocId;
	}

	public void setResourceDocId(long value) {
		this.resourceDocId = value;
	}

	public GrantDenyFlg getGrantDenyFlg() {
		return this.grantDenyFlg;
	}

	public void setGrantDenyFlg(GrantDenyFlg value) {
		this.grantDenyFlg = value;
	}

	public long getApplicationId() {
		return this.applicationId;
	}

	public void setApplicationId(long value) {
		this.applicationId = value;
	}

	public long getCustAuthZDocId() {
		return this.custAuthZDocId;
	}

	public void setCustAuthZDocId(long value) {
		this.custAuthZDocId = value;
	}

	public long getActionDocId() {
		return this.actionDocId;
	}

	public void setActionDocId(long value) {
		this.actionDocId = value;
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
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\cds\authZ\Rule.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */