package com.fedex.framework.cds;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "changeContextType", propOrder = {"userId", "reason", "searchValue"})
public class ChangeContextType {
	protected String userId;
	protected String reason;
	protected String searchValue;

	public String getUserId() {
		return this.userId;
	}

	public void setUserId(String value) {
		this.userId = value;
	}

	public String getReason() {
		return this.reason;
	}

	public void setReason(String value) {
		this.reason = value;
	}

	public String getSearchValue() {
		return this.searchValue;
	}

	public void setSearchValue(String value) {
		this.searchValue = value;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\framework\cds\ChangeContextType.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */