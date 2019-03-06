package com.fedex.enterprise.security.customauthz;

import com.fedex.enterprise.security.utils.SecurityDataBaseClass;

import java.io.Serializable;

public class CustomAuthzData
		extends SecurityDataBaseClass
		implements Serializable {
	private static final long serialVersionUID = 1L;
	private String classNm;
	private String classDesc;

	public SecurityDataBaseClass.DATA_TYPE getDataType() {
		return SecurityDataBaseClass.DATA_TYPE.CUSTOM_AUTHZ;
	}

	public String getClassNm() {
		return this.classNm;
	}

	public void setClassNm(String classNm) {
		this.classNm = classNm;
	}

	public String getClassDesc() {
		return this.classDesc;
	}

	public void setClassDesc(String classDesc) {
		this.classDesc = classDesc;
	}

	public String toString() {
		return "[docId:" + getDocId() + ",classNm:" + this.classNm + ",classDesc:" + this.classDesc + ",appId:" + getAppId() + "]";
	}

	public boolean validate() {
		super.validate();
		super.validateString(this.classNm, "Class name", false, null, 1, 96);
		super.validateString(this.classDesc, "Class description", true, null, 0, 128);
		return this.validationError.length() == 0;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\customauthz\CustomAuthzData.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */