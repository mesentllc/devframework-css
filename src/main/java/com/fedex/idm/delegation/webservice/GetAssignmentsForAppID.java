package com.fedex.idm.delegation.webservice;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "getAssignmentsForAppID", propOrder = {"appId", "function"})
public class GetAssignmentsForAppID {
	protected String appId;
	protected String function;

	public String getAppId() {
		return this.appId;
	}

	public void setAppId(String value) {
		this.appId = value;
	}

	public String getFunction() {
		return this.function;
	}

	public void setFunction(String value) {
		this.function = value;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\idm\delegation\webservice\GetAssignmentsForAppID.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */