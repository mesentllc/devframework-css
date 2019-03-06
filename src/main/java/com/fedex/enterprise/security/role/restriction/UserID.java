package com.fedex.enterprise.security.role.restriction;

import java.io.Serializable;

public class UserID
		implements Serializable {
	private static final long serialVersionUID = 1L;
	private String empNbr;
	private String firstName;
	private String lastName;
	private String groupNm;
	boolean hasRestriction = false;

	public String getEmpNbr() {
		return this.empNbr;
	}

	public void setEmpNbr(String empNbr) {
		this.empNbr = empNbr;
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

	public String getGroupNm() {
		return this.groupNm;
	}

	public void setGroupNm(String groupNm) {
		this.groupNm = groupNm;
	}

	public boolean isHasRestriction() {
		return this.hasRestriction;
	}

	public void setHasRestriction(boolean hasRestriction) {
		this.hasRestriction = hasRestriction;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\role\restriction\UserID.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */