package com.fedex.enterprise.security.action;

import com.fedex.enterprise.security.utils.SecurityDataBaseClass;

import java.io.Serializable;

public class ActionData
		extends SecurityDataBaseClass
		implements Serializable {
	private static final long serialVersionUID = 1L;
	private String actionNm;
	private String actionDesc;
	private boolean view;
	private boolean modify;
	private boolean delete;

	public SecurityDataBaseClass.DATA_TYPE getDataType() {
		return SecurityDataBaseClass.DATA_TYPE.ACTION;
	}

	public String getActionNm() {
		return this.actionNm;
	}

	public void setActionNm(String actionNm) {
		this.actionNm = actionNm;
	}

	public String getActionDesc() {
		return this.actionDesc;
	}

	public void setActionDesc(String actionDesc) {
		this.actionDesc = actionDesc;
	}

	public boolean isView() {
		return this.view;
	}

	public void setView(boolean view) {
		this.view = view;
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
		return "ActionData [actionDesc=" + this.actionDesc + ", actionNm=" + this.actionNm + ", delete=" + this.delete + ", docId=" + getDocId() + ", modify=" + this.modify + ", view=" + this.view + "]";
	}

	public boolean validate() {
		super.validate();
		super.validateString(super.getAppId(), "Application ID", false, null, 1, 10);
		super.validateString(this.actionNm, "Action name", false, SecurityDataBaseClass.SECURITY_NAME_PATTERN, 1, 32);
		super.validateString(this.actionDesc, "Action description", true, SecurityDataBaseClass.SECURITY_DESC_PATTERN, 0, 128);
		return this.validationError.length() == 0;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\action\ActionData.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */