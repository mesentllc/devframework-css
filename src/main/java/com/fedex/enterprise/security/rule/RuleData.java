package com.fedex.enterprise.security.rule;

import com.fedex.enterprise.security.customauthz.CustomAuthzData;
import com.fedex.enterprise.security.utils.SecurityDataBaseClass;

import java.io.Serializable;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

public class RuleData
		extends SecurityDataBaseClass
		implements Serializable {
	private static final long serialVersionUID = 1L;
	private static final Pattern GRANT_FLAG_PATTERN = Pattern.compile("[N]{1}|[Y]{1}|[n]{1}|[y]{1}");
	private long roleDocId;
	private long resDocId;
	private long actionDocId;
	private long custAuthZDocId;
	private char grantFlg = 'Y';
	private List<ExtendedRuleData> extendedRuleList;
	private List<CustomAuthzData> custAuthzList;
	private String roleNm;
	private String resourceNm;
	private String actionNm;
	private String custAuthZClassNm;
	private String grantMsg;
	private String[] extendedRuleGuiList;
	private boolean selected;
	private boolean custAuthzExist;
	private boolean extdRuleExist;

	public SecurityDataBaseClass.DATA_TYPE getDataType() {
		return SecurityDataBaseClass.DATA_TYPE.RULE;
	}

	public boolean isSelected() {
		return this.selected;
	}

	public void setSelected(boolean selected) {
		this.selected = selected;
	}

	public String[] getExtendedRuleGuiList() {
		if (this.extendedRuleGuiList != null) {
			return this.extendedRuleGuiList.clone();
		}
		return null;
	}

	public void setExtendedRuleGuiList(String[] extendedRuleGuiList) {
		if (extendedRuleGuiList == null) {
			this.extendedRuleGuiList = null;
		}
		else {
			this.extendedRuleGuiList = extendedRuleGuiList.clone();
		}
	}

	public long getRoleDocId() {
		return this.roleDocId;
	}

	public void setRoleDocId(long roleDocId) {
		this.roleDocId = roleDocId;
	}

	public long getResDocId() {
		return this.resDocId;
	}

	public void setResDocId(long resDocId) {
		this.resDocId = resDocId;
	}

	public long getActionDocId() {
		return this.actionDocId;
	}

	public void setActionDocId(long actionDocId) {
		this.actionDocId = actionDocId;
	}

	public long getCustAuthZDocId() {
		return this.custAuthZDocId;
	}

	public void setCustAuthZDocId(long custAuthZDocId) {
		this.custAuthZDocId = custAuthZDocId;
	}

	public char getGrantFlg() {
		return this.grantFlg;
	}

	public void setGrantFlg(char grantFlg) {
		this.grantFlg = grantFlg;
	}

	public List<ExtendedRuleData> getExtendedRuleList() {
		return this.extendedRuleList;
	}

	public void setExtendedRuleList(List<ExtendedRuleData> extendedRuleList) {
		this.extendedRuleList = extendedRuleList;
	}

	public String getRoleNm() {
		return this.roleNm;
	}

	public void setRoleNm(String roleNm) {
		this.roleNm = roleNm;
	}

	public String getResourceNm() {
		return this.resourceNm;
	}

	public void setResourceNm(String resourceNm) {
		this.resourceNm = resourceNm;
	}

	public String getActionNm() {
		return this.actionNm;
	}

	public void setActionNm(String actionNm) {
		this.actionNm = actionNm;
	}

	public String getCustAuthZClassNm() {
		return this.custAuthZClassNm;
	}

	public void setCustAuthZClassNm(String custAuthZClassNm) {
		this.custAuthZClassNm = custAuthZClassNm;
	}

	public String getGrantMsg() {
		String returnVal = "is NOT allowed to";
		if (this.grantFlg == 'Y') {
			returnVal = "is allowed to";
		}
		return returnVal;
	}

	public void setGrantMsg(String grantMsg) {
		this.grantMsg = grantMsg;
	}

	public String toString() {
		return "RuleData [actionDocId=" + this.actionDocId + ", actionNm=" + this.actionNm + ", custAuthZClassNm=" + this.custAuthZClassNm + ", custAuthZDocId=" + this.custAuthZDocId + ", docId=" + getDocId() + ", extendedRuleGuiList=" + Arrays.toString(this.extendedRuleGuiList) + ", extendedRuleList=" + ", custAuthzList=" + this.custAuthzList + this.extendedRuleList + ", grantFlg=" + this.grantFlg + ", grantMsg=" + this.grantMsg + ", resDocId=" + this.resDocId + ", resourceNm=" + this.resourceNm + ", roleDocId=" + this.roleDocId + ", roleNm=" + this.roleNm + ", selected=" + this.selected + "]";
	}

	public List<CustomAuthzData> getCustAuthzList() {
		return this.custAuthzList;
	}

	public void setCustAuthzList(List<CustomAuthzData> custAuthzList) {
		this.custAuthzList = custAuthzList;
	}

	public boolean isCustAuthzExist() {
		return this.custAuthzExist;
	}

	public void setCustAuthzExist(boolean isCustAuthzExist) {
		this.custAuthzExist = isCustAuthzExist;
	}

	public boolean isExtdRuleExist() {
		return this.extdRuleExist;
	}

	public void setExtdRuleExist(boolean extdRuleExist) {
		this.extdRuleExist = extdRuleExist;
	}

	public boolean validate() {
		super.validate();
		super.validateString(super.getAppId(), "Application ID", false, null, 1, 10);
		super.validateString(Character.toString(this.grantFlg), "Grant/Deny flag", false, GRANT_FLAG_PATTERN, 1, 1);
		if (this.roleDocId == 0L) {
			this.validationError.append("Role ID is zero.  ");
		}
		if (this.resDocId == 0L) {
			this.validationError.append("Resource ID is zero.  ");
		}
		if (this.actionDocId == 0L) {
			this.validationError.append("Action ID is zero.  ");
		}
		return this.validationError.length() == 0;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\rule\RuleData.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */