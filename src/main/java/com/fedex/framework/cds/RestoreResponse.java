package com.fedex.framework.cds;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import java.util.ArrayList;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {"restoreItem"})
@XmlRootElement(name = "restoreResponse")
public class RestoreResponse {
	@XmlElement(required = true)
	protected List<KeyedStanzasType> restoreItem;

	public List<KeyedStanzasType> getRestoreItem() {
		if (this.restoreItem == null) {
			this.restoreItem = new ArrayList();
		}
		return this.restoreItem;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\framework\cds\RestoreResponse.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */