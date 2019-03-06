package com.fedex.enterprise.security.utils;

import java.io.Serializable;
import java.util.Date;
import java.util.regex.Pattern;

public class SecurityDataBaseClass
		implements Serializable {
	private static final long serialVersionUID = 1L;
	protected static final Pattern SECURITY_NAME_PATTERN = Pattern.compile("[a-zA-Z0-9_-][a-zA-Z0-9_-][a-zA-Z0-9_-]+|[*]{1}");
	protected static final Pattern SECURITY_DESC_PATTERN = Pattern.compile("[a-zA-Z0-9\\_\\-\\ ]*");
	private String appId;

	public enum DATA_TYPE {
		BASE,
		ACTION,
		CUSTOM_AUTHZ,
		EXTENDED_RULE,
		EXTENDED_RULE_XREF,
		RESOURCE,
		RESTRICTION,
		ROLE,
		RULE,
		APP_ROLE,
		GROUP_ROLE,
		USER_ROLE;

		DATA_TYPE() {
		}
	}

	private long docId;
	private Date lastUpdated;
	protected transient StringBuilder validationError = new StringBuilder();

	public String getAppId() {
		return this.appId;
	}

	public void setAppId(String appId) {
		this.appId = appId;
	}

	public DATA_TYPE getDataType() {
		return DATA_TYPE.BASE;
	}

	public long getDocId() {
		return this.docId;
	}

	public void setDocId(long documentId) {
		this.docId = documentId;
	}

	public Date getLastUpdated() {
		if (this.lastUpdated != null) {
			return new Date(this.lastUpdated.getTime());
		}
		return null;
	}

	public void setLastUpdated(Date lastUpdated) {
		if (lastUpdated == null) {
			this.lastUpdated = lastUpdated;
		}
		else {
			this.lastUpdated = new Date(lastUpdated.getTime());
		}
	}

	public boolean validate() {
		this.validationError.setLength(0);
		return true;
	}

	public String getValidationError() {
		return this.validationError.toString();
	}

	protected void validateString(String input, String inputDesc, boolean AllowNull, Pattern regEx, int minLength, int maxLength) {
		if ((input == null) && (!AllowNull)) {
			this.validationError.append(inputDesc).append(" is null.  ");
		}
		if (input != null) {
			if ((regEx != null) && (!regEx.matcher(input).matches())) {
				this.validationError.append(inputDesc).append(" (").append(input).append(") does not match the regular expression \"").append(regEx.toString()).append("\".  ");
			}
			if (input.length() < minLength) {
				this.validationError.append(inputDesc).append(" (").append(input).append(")  length is less than the min allowed amount of ").append(minLength).append(".  ");
			}
			if (input.length() > maxLength) {
				this.validationError.append(inputDesc).append(" (").append(input).append(")  length is longer than the max allowed amount of ").append(maxLength).append(".  ");
			}
		}
	}
}