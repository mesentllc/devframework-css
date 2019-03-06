package com.fedex.enterprise.security.rule;

import com.fedex.enterprise.security.utils.SecurityDataBaseClass;

import java.io.Serializable;
import java.util.regex.Pattern;

public class ExtendedRuleData
		extends SecurityDataBaseClass
		implements Serializable {
	private static final long serialVersionUID = 1L;
	protected static final Pattern KEY_PATTERN = Pattern.compile("[a-zA-Z0-9\\_\\-]+");
	protected static final Pattern VALUE_PATTERN = Pattern.compile("[/a-zA-Z0-9\\.\\_\\-\\:\\/]+");
	private String extRuleKey;
	private String extRuleOperator;
	private String extRuleValue;
	private String extRuleType;
	private boolean assigned;

	public SecurityDataBaseClass.DATA_TYPE getDataType() {
		return SecurityDataBaseClass.DATA_TYPE.EXTENDED_RULE;
	}

	public String getExtRuleKey() {
		return this.extRuleKey;
	}

	public void setExtRuleKey(String extRuleKey) {
		this.extRuleKey = extRuleKey;
	}

	public String getExtRuleOperator() {
		return this.extRuleOperator;
	}

	public void setExtRuleOperator(String extRuleOperator) {
		this.extRuleOperator = extRuleOperator;
	}

	public String getExtRuleValue() {
		return this.extRuleValue;
	}

	public void setExtRuleValue(String extRuleValue) {
		this.extRuleValue = extRuleValue;
	}

	public String getExtRuleType() {
		return this.extRuleType;
	}

	public void setExtRuleType(String extRuleType) {
		this.extRuleType = extRuleType;
	}

	public boolean isAssigned() {
		return this.assigned;
	}

	public void setAssigned(boolean assigned) {
		this.assigned = assigned;
	}

	public String toString() {
		return "ExtendedRuleData [assigned=" + this.assigned + ", docId=" + getDocId() + ", extRuleKey=" + this.extRuleKey + ", extRuleOperator=" + this.extRuleOperator + ", extRuleType=" + this.extRuleType + ", extRuleValue=" + this.extRuleValue + "]";
	}

	public boolean validate() {
		super.validate();
		super.validateString(super.getAppId(), "Application ID", false, null, 1, 10);
		super.validateString(this.extRuleKey, "Extended rule key", false, KEY_PATTERN, 1, 40);
		super.validateString(this.extRuleOperator, "Extended rule operator", false, null, 1, 24);
		super.validateString(this.extRuleValue, "Extended rule value", false, VALUE_PATTERN, 1, 64);
		super.validateString(this.extRuleType, "Extended rule type", false, null, 1, 16);
		return this.validationError.length() == 0;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\rule\ExtendedRuleData.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */