package com.fedex.enterprise.security.role;

import com.fedex.enterprise.security.utils.SecurityDataBaseClass;

import java.io.Serializable;
import java.util.GregorianCalendar;

public class AppRoleData
		extends SecurityDataBaseClass
		implements Serializable {
	private static final long serialVersionUID = 1L;
	private long roleDocId;
	private String applicationName;
	private String assignedBy;
	private GregorianCalendar dateAssigned;

	public SecurityDataBaseClass.DATA_TYPE getDataType() {
		return SecurityDataBaseClass.DATA_TYPE.APP_ROLE;
	}

	public long getRoleDocId() {
		return this.roleDocId;
	}

	public void setRoleDocId(long roleDocId) {
		this.roleDocId = roleDocId;
	}

	public String getApplicationName() {
		return this.applicationName;
	}

	public void setApplicationName(String applicationName) {
		this.applicationName = applicationName;
	}

	public String getAssignedBy() {
		return this.assignedBy;
	}

	public GregorianCalendar getDateAssigned() {
		return this.dateAssigned;
	}

	public void setAssignedBy(String assignedBy) {
		this.assignedBy = assignedBy;
	}

	public void setDateAssigned(GregorianCalendar dateAssigned) {
		this.dateAssigned = dateAssigned;
	}

	public String toString() {
		return "AppRoleData [applicationId=" + getAppId() + ", applicationName=" + this.applicationName + ", docId=" + getDocId() + ", roleDocId=" + this.roleDocId + "]";
	}

	public boolean validate() {
		super.validate();
		super.validateString(getAppId(), "Application ID", false, null, 1, 10);
		if (this.roleDocId == 0L) {
			this.validationError.append("Role ID is zero.  ");
		}
		return this.validationError.length() == 0;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\role\AppRoleData.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */