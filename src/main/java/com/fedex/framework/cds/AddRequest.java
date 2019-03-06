package com.fedex.framework.cds;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import java.util.ArrayList;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {"addItem"})
@XmlRootElement(name = "addRequest")
public class AddRequest {
	@XmlElement(required = true)
	protected List<KeyedDocumentType> addItem;

	public List<KeyedDocumentType> getAddItem() {
		if (this.addItem == null) {
			this.addItem = new ArrayList();
		}
		return this.addItem;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\framework\cds\AddRequest.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */