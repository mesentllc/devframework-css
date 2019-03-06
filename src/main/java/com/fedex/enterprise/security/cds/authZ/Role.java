package com.fedex.enterprise.security.cds.authZ;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "")
@XmlRootElement(name = "role")
public class Role {
	@XmlAttribute(name = "RoleName", required = true)
	protected String roleName;
	@XmlAttribute(name = "RoleDesc", required = true)
	protected String roleDesc;
	@XmlAttribute(name = "RoleScopeType", required = true)
	protected String roleScopeType;
	@XmlAttribute(name = "RoleScopeName", required = true)
	protected String roleScopeName;
	@XmlAttribute(required = true)
	protected String domain;
	@XmlAttribute(required = true)
	protected int majorVersion;
	@XmlAttribute(required = true)
	protected int minorVersion;

	public String getRoleName() {
		return this.roleName;
	}

	public void setRoleName(String value) {
		this.roleName = value;
	}

	public String getRoleDesc() {
		return this.roleDesc;
	}

	public void setRoleDesc(String value) {
		this.roleDesc = value;
	}

	public String getRoleScopeType() {
		return this.roleScopeType;
	}

	public void setRoleScopeType(String value) {
		this.roleScopeType = value;
	}

	public String getRoleScopeName() {
		return this.roleScopeName;
	}

	public void setRoleScopeName(String value) {
		this.roleScopeName = value;
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
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\cds\authZ\Role.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */