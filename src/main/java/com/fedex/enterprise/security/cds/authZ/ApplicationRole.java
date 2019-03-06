package com.fedex.enterprise.security.cds.authZ;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import javax.xml.datatype.XMLGregorianCalendar;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "")
@XmlRootElement(name = "applicationRole")
public class ApplicationRole {
	@XmlAttribute(name = "RoleDocId", required = true)
	protected long roleDocId;
	@XmlAttribute(name = "ApplicationId", required = true)
	protected long applicationId;
	@XmlAttribute(name = "AssignedBy")
	protected String assignedBy;
	@XmlAttribute(name = "DateAssigned")
	protected XMLGregorianCalendar dateAssigned;
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

	public long getApplicationId() {
		return this.applicationId;
	}

	public void setApplicationId(long value) {
		this.applicationId = value;
	}

	public String getAssignedBy() {
		return this.assignedBy;
	}

	public void setAssignedBy(String value) {
		this.assignedBy = value;
	}

	public XMLGregorianCalendar getDateAssigned() {
		return this.dateAssigned;
	}

	public void setDateAssigned(XMLGregorianCalendar value) {
		this.dateAssigned = value;
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
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\cds\authZ\ApplicationRole.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */