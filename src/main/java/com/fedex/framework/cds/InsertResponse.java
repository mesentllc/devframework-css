package com.fedex.framework.cds;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import java.util.ArrayList;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {"insertItem"})
@XmlRootElement(name = "insertResponse")
public class InsertResponse {
	protected List<KeyedStanzasType> insertItem;

	public List<KeyedStanzasType> getInsertItem() {
		if (this.insertItem == null) {
			this.insertItem = new ArrayList();
		}
		return this.insertItem;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\framework\cds\InsertResponse.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */