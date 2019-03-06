package com.fedex.idm.delegation.webservice;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import java.util.ArrayList;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "getAssignmentsResponse", propOrder = {"_return"})
public class GetAssignmentsResponse {
	@XmlElement(name = "return")
	protected List<Object> _return;

	public List<Object> getReturn() {
		if (this._return == null) {
			this._return = new ArrayList();
		}
		return this._return;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\idm\delegation\webservice\GetAssignmentsResponse.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */