package com.fedex.enterprise.security.role;

import com.fedex.enterprise.security.role.restriction.RestrictionData;
import com.fedex.enterprise.security.utils.SecurityDataBaseClass;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class RoleData
		extends SecurityDataBaseClass
		implements Serializable {
	private static final long serialVersionUID = 1L;
	private String roleNm = "";
	private String roleDesc = "";
	private String roleTypeCd = "";
	private String roleScopeNm = "";
	private List<GroupRoleData> groupMemberList = new ArrayList();
	private List<UserRoleData> userMemberList = new ArrayList();
	private List<AppRoleData> appMemberList = new ArrayList();
	private List<RestrictionData> restrictionMemberList = new ArrayList();
	private List<RoleOwnerData> roleOwnerList = new ArrayList();
	private boolean view;
	private boolean manage;
	private boolean modify;
	private boolean delete;
	private boolean update = false;

	public SecurityDataBaseClass.DATA_TYPE getDataType() {
		return SecurityDataBaseClass.DATA_TYPE.ROLE;
	}

	public boolean isUpdate() {
		return this.update;
	}

	public void setUpdate(boolean update) {
		this.update = update;
	}

	public List<RoleOwnerData> getRoleOwnerList() {
		return this.roleOwnerList;
	}

	public void setRoleOwnerList(List<RoleOwnerData> roleOwnerList) {
		this.roleOwnerList = roleOwnerList;
	}

	public List<GroupRoleData> getGroupMemberList() {
		return this.groupMemberList;
	}

	public void setGroupMemberList(List<GroupRoleData> groupMemberList) {
		this.groupMemberList = groupMemberList;
	}

	public List<UserRoleData> getUserMemberList() {
		return this.userMemberList;
	}

	public void setUserMemberList(List<UserRoleData> userMemberList) {
		this.userMemberList = userMemberList;
	}

	public List<AppRoleData> getAppMemberList() {
		return this.appMemberList;
	}

	public void setAppMemberList(List<AppRoleData> appMemberList) {
		this.appMemberList = appMemberList;
	}

	public String getRoleNm() {
		return this.roleNm;
	}

	public void setRoleNm(String roleNm) {
		this.roleNm = roleNm;
	}

	public String getRoleDesc() {
		return this.roleDesc;
	}

	public void setRoleDesc(String roleDesc) {
		this.roleDesc = roleDesc;
	}

	public String getRoleTypeCd() {
		return this.roleTypeCd;
	}

	public void setRoleTypeCd(String roleTypeCd) {
		this.roleTypeCd = roleTypeCd;
	}

	public String getRoleScopeNm() {
		return this.roleScopeNm;
	}

	public void setRoleScopeNm(String roleScopeNm) {
		this.roleScopeNm = roleScopeNm;
	}

	public boolean isSelected() {
		return this.selected;
	}

	public void setSelected(boolean selected) {
		this.selected = selected;
	}

	public boolean isView() {
		return this.view;
	}

	public void setView(boolean view) {
		this.view = view;
	}

	public boolean isManage() {
		return this.manage;
	}

	public void setManage(boolean manage) {
		this.manage = manage;
	}

	public boolean isModify() {
		return this.modify;
	}

	public void setModify(boolean modify) {
		this.modify = modify;
	}

	public boolean isDelete() {
		return this.delete;
	}

	public void setDelete(boolean delete) {
		this.delete = delete;
	}

	public String toString() {
		return "RoleData [appMemberList=" + this.appMemberList + ", delete=" + this.delete + ", docId=" + getDocId() + ", groupMemberList=" + this.groupMemberList + ", manage=" + this.manage + ", modify=" + this.modify + ", roleDesc=" + this.roleDesc + ", roleNm=" + this.roleNm + ", roleOwnerList=" + this.roleOwnerList + ", roleScopeNm=" + this.roleScopeNm + ", roleTypeCd=" + this.roleTypeCd + ", selected=" + this.selected + ", userMemberList=" + this.userMemberList + ", view=" + this.view + "]";
	}

	private boolean selected;

	public List<RestrictionData> getRestrictionMemberList() {
		return this.restrictionMemberList;
	}

	public void setRestrictionMemberList(List<RestrictionData> restrictionMemberList) {
		this.restrictionMemberList = restrictionMemberList;
	}

	public boolean validate() {
		super.validate();
		super.validateString(this.roleNm, "Role name", false, SecurityDataBaseClass.SECURITY_NAME_PATTERN, 1, 64);
		super.validateString(this.roleDesc, "Role description", false, null, 1, 128);
		super.validateString(this.roleTypeCd, "Role type", false, null, 1, 32);
		super.validateString(this.roleScopeNm, "Role scope", false, null, 1, 32);
		return this.validationError.length() == 0;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\role\RoleData.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */