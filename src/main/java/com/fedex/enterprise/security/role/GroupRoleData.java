package com.fedex.enterprise.security.role;

import com.fedex.enterprise.security.utils.SecurityDataBaseClass;

import java.io.Serializable;
import java.util.GregorianCalendar;

public class GroupRoleData
		extends SecurityDataBaseClass
		implements Serializable {
	private static final long serialVersionUID = 1L;
	private long roleDocId;
	private String groupNm;
	private String assignedBy;
	private GregorianCalendar dateAssigned;

	public SecurityDataBaseClass.DATA_TYPE getDataType() {
		return SecurityDataBaseClass.DATA_TYPE.GROUP_ROLE;
	}

	public long getRoleDocId() {
		return this.roleDocId;
	}

	public void setRoleDocId(long roleDocId) {
		this.roleDocId = roleDocId;
	}

	public String getGroupNm() {
		return this.groupNm;
	}

	public void setGroupNm(String groupNm) {
		this.groupNm = groupNm;
	}

	public String getAssignedBy() {
		return this.assignedBy;
	}

	public void setAssignedBy(String assignedBy) {
		this.assignedBy = assignedBy;
	}

	public GregorianCalendar getDateAssigned() {
		return this.dateAssigned;
	}

	public void setDateAssigned(GregorianCalendar dateAssigned) {
		this.dateAssigned = dateAssigned;
	}

	public String toString() {
		return "[docId:" + getDocId() + ",roleDocId:" + this.roleDocId + ",groupNm:" + this.groupNm + "]";
	}

	public boolean validate() {
		super.validate();
		super.validateString(this.groupNm, "Group name", false, null, 1, 64);
		if (this.roleDocId == 0L) {
			this.validationError.append("Role ID is zero.  ");
		}
		return this.validationError.length() == 0;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\role\GroupRoleData.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */