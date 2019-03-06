package com.fedex.enterprise.security.role;

import com.fedex.enterprise.security.utils.SecurityDataBaseClass;

import java.io.Serializable;

public class RoleOwnerData
		extends SecurityDataBaseClass
		implements Serializable {
	private static final long serialVersionUID = 1L;
	private long roleDocId;
	private int empNbr;

	public long getRoleDocId() {
		return this.roleDocId;
	}

	public void setRoleDocId(long roleDocId) {
		this.roleDocId = roleDocId;
	}

	public int getEmpNbr() {
		return this.empNbr;
	}

	public void setEmpNbr(int empNbr) {
		this.empNbr = empNbr;
	}

	public String toString() {
		return "[docId:" + getDocId() + ",roleDocId:" + this.roleDocId + ",empNbr:" + this.empNbr + ",appId:" + getAppId() + "]";
	}

	public boolean validate() {
		super.validate();
		if (this.empNbr == 0) {
			this.validationError.append("Employee ID is zero.  ");
		}
		if (this.roleDocId == 0L) {
			this.validationError.append("Role ID is zero.  ");
		}
		return this.validationError.length() == 0;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\role\RoleOwnerData.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */