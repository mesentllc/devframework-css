package com.fedex.enterprise.security.role;

import com.fedex.enterprise.security.utils.SecurityDataBaseClass;

import java.io.Serializable;
import java.util.GregorianCalendar;

public class UserRoleData
		extends SecurityDataBaseClass
		implements Serializable {
	private static final long serialVersionUID = 1L;
	private long roleDocId;
	private String empNbr;
	private String firstName;
	private String lastName;
	private String assignedBy;
	private GregorianCalendar dateAssigned;

	public SecurityDataBaseClass.DATA_TYPE getDataType() {
		return SecurityDataBaseClass.DATA_TYPE.USER_ROLE;
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

	public String getEmpNbr() {
		return this.empNbr;
	}

	public void setEmpNbr(String empNbr) {
		this.empNbr = empNbr;
	}

	public long getRoleDocId() {
		return this.roleDocId;
	}

	public void setRoleDocId(long roleDocId) {
		this.roleDocId = roleDocId;
	}

	public String getFirstName() {
		return this.firstName;
	}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}

	public String getLastName() {
		return this.lastName;
	}

	public void setLastName(String lastName) {
		this.lastName = lastName;
	}

	public String toString() {
		return "UserRoleData [docId=" + getDocId() + ", empNbr=" + this.empNbr + ", firstName=" + this.firstName + ", lastName=" + this.lastName + ", roleDocId=" + this.roleDocId + "]";
	}

	public boolean validate() {
		super.validate();
		super.validateString(this.empNbr, "User ID", false, null, 1, 32);
		if (this.roleDocId == 0L) {
			this.validationError.append("Role ID is zero.  ");
		}
		return this.validationError.length() == 0;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\role\UserRoleData.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */