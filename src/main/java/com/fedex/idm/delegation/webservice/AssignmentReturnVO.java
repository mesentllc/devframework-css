package com.fedex.idm.delegation.webservice;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "assignmentReturnVO", propOrder = {"delegate", "delegator", "function"})
public class AssignmentReturnVO {
	protected String delegate;
	protected String delegator;
	protected String function;

	public String getDelegate() {
		return this.delegate;
	}

	public void setDelegate(String value) {
		this.delegate = value;
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
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\idm\delegation\webservice\AssignmentReturnVO.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */