package com.fedex.idm.delegation.webservice;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "getAssignments", propOrder = {"appId", "delegatee", "delegator", "function"})
public class GetAssignments {
	protected String appId;
	protected String delegatee;
	protected String delegator;
	protected String function;

	public String getAppId() {
		return this.appId;
	}

	public void setAppId(String value) {
		this.appId = value;
	}

	public String getDelegatee() {
		return this.delegatee;
	}

	public void setDelegatee(String value) {
		this.delegatee = value;
	}

	public String getDelegator() {
		return this.delegator;
	}

	public void setDelegator(String value) {
		this.delegator = value;
	}

	public String getFunction() {
		return this.function;
	}

	public void setFunction(String value) {
		this.function = value;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\idm\delegation\webservice\GetAssignments.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */