package com.fedex.enterprise.security.rule;

import com.fedex.enterprise.security.utils.SecurityDataBaseClass;

import java.io.Serializable;

public class ExtendedRuleXrefData
		extends SecurityDataBaseClass
		implements Serializable {
	private static final long serialVersionUID = 1L;
	private long ruleDocId;
	private long extRuleDocId;

	public SecurityDataBaseClass.DATA_TYPE getDataType() {
		return SecurityDataBaseClass.DATA_TYPE.EXTENDED_RULE_XREF;
	}

	public long getRuleDocId() {
		return this.ruleDocId;
	}

	public void setRuleDocId(long ruleDocId) {
		this.ruleDocId = ruleDocId;
	}

	public long getExtRuleDocId() {
		return this.extRuleDocId;
	}

	public void setExtRuleDocId(long extRuleDocId) {
		this.extRuleDocId = extRuleDocId;
	}

	public String toString() {
		return "ExtendedRuleXrefData [docId=" + getDocId() + ", extRuleDocId=" + this.extRuleDocId + ", ruleDocId=" + this.ruleDocId + "]";
	}

	public boolean validate() {
		super.validate();
		super.validateString(super.getAppId(), "Application ID", false, null, 1, 10);
		if (this.ruleDocId == 0L) {
			this.validationError.append("Rule ID is zero.  ");
		}
		if (this.extRuleDocId == 0L) {
			this.validationError.append("Extended rule ID is zero.  ");
		}
		return this.validationError.length() == 0;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\rule\ExtendedRuleXrefData.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */