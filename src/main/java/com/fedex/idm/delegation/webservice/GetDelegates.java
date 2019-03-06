package com.fedex.idm.delegation.webservice;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "getDelegates", propOrder = {"arg0", "arg1"})
public class GetDelegates {
	protected String arg0;
	protected String arg1;

	public String getArg0() {
		return this.arg0;
	}

	public void setArg0(String value) {
		this.arg0 = value;
	}

	public String getArg1() {
		return this.arg1;
	}

	public void setArg1(String value) {
		this.arg1 = value;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\idm\delegation\webservice\GetDelegates.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */