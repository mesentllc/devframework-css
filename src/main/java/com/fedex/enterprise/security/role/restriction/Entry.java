package com.fedex.enterprise.security.role.restriction;

import com.fedex.enterprise.security.utils.SecurityDataBaseClass;

import java.io.Serializable;

public class Entry extends SecurityDataBaseClass implements Serializable {
	private static final long serialVersionUID = 1L;
	private String key = "";
	private String value = "";

	public String getKey() {
		return this.key;
	}

	public void setKey(String key) {
		this.key = key;
	}

	public String getValue() {
		return this.value;
	}

	public void setValue(String value) {
		this.value = value;
	}

	public String toString() {
		return "Entry [key=" + this.key + ", value=" + this.value + "]";
	}

	public boolean validate() {
		super.validate();
		super.validateString(this.key, "Entry key", false, null, 1, 255);
		super.validateString(this.value, "Entry value", false, null, 1, 255);
		return this.validationError.length() == 0;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\role\restriction\Entry.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */