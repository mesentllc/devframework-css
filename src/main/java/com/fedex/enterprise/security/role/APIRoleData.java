package com.fedex.enterprise.security.role;

import com.fedex.enterprise.security.utils.SecurityDataBaseClass;

import java.io.Serializable;
import java.util.List;

public class APIRoleData
		extends SecurityDataBaseClass
		implements Serializable {
	private static final long serialVersionUID = 1L;
	private long docId;
	private String roleNm;
	private List<String> groupMemberList;
	private List<String> userMemberList;
	private List<String> appMemberList;

	public List<String> getGroupMemberList() {
		return this.groupMemberList;
	}

	public void setGroupMemberList(List<String> groupMemberList) {
		this.groupMemberList = groupMemberList;
	}

	public List<String> getUserMemberList() {
		return this.userMemberList;
	}

	public void setUserMemberList(List<String> userMemberList) {
		this.userMemberList = userMemberList;
	}

	public List<String> getAppMemberList() {
		return this.appMemberList;
	}

	public void setAppMemberList(List<String> appMemberList) {
		this.appMemberList = appMemberList;
	}

	public long getDocId() {
		return this.docId;
	}

	public void setDocId(long docId) {
		this.docId = docId;
	}

	public String getRoleNm() {
		return this.roleNm;
	}

	public void setRoleNm(String roleNm) {
		this.roleNm = roleNm;
	}

	public String toString() {
		return "APIRoleData [appMemberList=" + this.appMemberList + ", docId=" + this.docId + ", groupMemberList=" + this.groupMemberList + ", roleNm=" + this.roleNm + ", userMemberList=" + this.userMemberList + "]";
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\role\APIRoleData.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */