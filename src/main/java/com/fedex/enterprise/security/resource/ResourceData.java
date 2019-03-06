package com.fedex.enterprise.security.resource;

import com.fedex.enterprise.security.utils.SecurityDataBaseClass;

import java.io.Serializable;
import java.util.regex.Pattern;

public class ResourceData
		extends SecurityDataBaseClass
		implements Serializable {
	private static final long serialVersionUID = 1L;
	protected static final Pattern RESOURCE_NAME_PATTERN = Pattern.compile("[$. /*a-zA-Z0-9_-][$. /*a-zA-Z0-9_-][$. /*a-zA-Z0-9_-]+|[*]{1}");
	private long resTypeDocId;
	private String resName;
	private String resDesc;
	private char rootFlg;
	private boolean selected;
	private boolean isRoot;
	private boolean wildcard;
	private boolean view;
	private boolean modify;
	private boolean delete;

	public SecurityDataBaseClass.DATA_TYPE getDataType() {
		return SecurityDataBaseClass.DATA_TYPE.RESOURCE;
	}

	public long getResTypeDocId() {
		return this.resTypeDocId;
	}

	public void setResTypeDocId(long resTypeDocId) {
		this.resTypeDocId = resTypeDocId;
	}

	public String getResName() {
		return this.resName;
	}

	public void setResName(String resName) {
		if ((resName != null) && (resName.endsWith("*"))) {
			this.wildcard = true;
		}
		this.resName = resName;
	}

	public String getResDesc() {
		return this.resDesc;
	}

	public void setResDesc(String resDesc) {
		this.resDesc = resDesc;
	}

	public char getRootFlg() {
		return this.rootFlg;
	}

	public void setRootFlg(char rootFlg) {
		this.rootFlg = rootFlg;
		this.isRoot = rootFlg == 'Y';
	}

	public boolean isWildcard() {
		return this.wildcard;
	}

	public void setWildcard(boolean wildcard) {
		this.wildcard = wildcard;
	}

	public boolean isSelected() {
		return this.selected;
	}

	public boolean isRoot() {
		return this.isRoot;
	}

	public void setSelected(boolean selected) {
		this.selected = selected;
	}

	public void setRoot(boolean isRoot) {
		this.isRoot = isRoot;
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
		return "ResourceData [delete=" + this.delete + ", docId=" + getDocId() + ", isRoot=" + this.isRoot + ", modify=" + this.modify + ", resDesc=" + this.resDesc + ", resName=" + this.resName + ", resTypeDocId=" + this.resTypeDocId + ", rootFlg=" + this.rootFlg + ", selected=" + this.selected + ", view=" + this.view + ", wildcard=" + this.wildcard + "]";
	}

	public boolean validate() {
		super.validate();
		super.validateString(super.getAppId(), "Application ID", false, null, 1, 10);
		super.validateString(this.resName, "Resource name", false, RESOURCE_NAME_PATTERN, 1, 128);
		super.validateString(this.resDesc, "Resource description", true, null, 0, 128);
		super.validateString(Character.toString(this.rootFlg), "Grant/Deny flag", false, null, 1, 1);
		return this.validationError.length() == 0;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\resource\ResourceData.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */