package com.fedex.enterprise.security.role.restriction;

import com.fedex.enterprise.security.utils.SecurityDataBaseClass;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class RestrictionData
		extends SecurityDataBaseClass
		implements Serializable {
	private static final long serialVersionUID = 1L;
	private static final Pattern EMP_ID_PATTERN = Pattern.compile("[0-9]{1,10}");
	private static final Pattern GROUP_NAME_PATTERN = Pattern.compile("[a-zA-Z0-9\\_\\-\\ ]+");
	public String roleNm = "";
	public String emplId = "";
	public long roleDocId;
	public String groupNm;
	private boolean selected;
	private List<RestrictionDataItem> restrictionList = new ArrayList();

	public SecurityDataBaseClass.DATA_TYPE getDataType() {
		return SecurityDataBaseClass.DATA_TYPE.RESTRICTION;
	}

	public String getRoleNm() {
		return this.roleNm;
	}

	public void setRoleNm(String roleNm) {
		this.roleNm = roleNm;
	}

	public String getEmplId() {
		return this.emplId;
	}

	public void setEmplId(String emplId) {
		this.emplId = emplId;
	}

	public long getRoleDocId() {
		return this.roleDocId;
	}

	public void setRoleDocId(long roleDocId) {
		this.roleDocId = roleDocId;
	}

	public String toString() {
		return "RestrictionData [appId=" + getAppId() + ", docId=" + getDocId() + ", emplId=" + this.emplId + ", restrictionItem=" + this.restrictionList + ", roleDocId=" + this.roleDocId + ", roleNm=" + this.roleNm + "]";
	}

	public List<RestrictionDataItem> getRestrictionList() {
		return this.restrictionList;
	}

	public void setRestrictionList(List<RestrictionDataItem> list) {
		this.restrictionList = list;
	}

	public String getGroupNm() {
		return this.groupNm;
	}

	public void setGroupNm(String groupNm) {
		this.groupNm = groupNm;
	}

	public boolean isSelected() {
		return this.selected;
	}

	public void setSelected(boolean selected) {
		this.selected = selected;
	}

	public boolean validate() {
		super.validate();
		super.validateString(super.getAppId(), "Application ID", false, null, 1, 10);
		super.validateString(this.roleNm, "", false, null, 1, 64);
		if ((this.emplId == null) && (this.groupNm == null)) {
			this.validationError.append("The restriction must be assigned to a user or group.  ");
		}
		else {
			if ((this.emplId != null) && (!this.emplId.isEmpty())) {
				super.validateString(this.emplId, "", false, EMP_ID_PATTERN, 1, 10);
			}
			else {
				super.validateString(this.groupNm, "", false, GROUP_NAME_PATTERN, 3, 50);
			}
		}
		if (this.roleDocId == 0L) {
			this.validationError.append("Role ID is zero.  ");
		}
		if ((this.restrictionList == null) || (this.restrictionList.size() == 0)) {
			this.validationError.append("Empty data item list.  ");
		}
		return this.validationError.length() == 0;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\role\restriction\RestrictionData.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */