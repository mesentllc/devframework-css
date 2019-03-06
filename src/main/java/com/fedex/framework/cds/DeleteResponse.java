package com.fedex.framework.cds;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import java.util.ArrayList;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {"deleteItem"})
@XmlRootElement(name = "deleteResponse")
public class DeleteResponse {
	protected List<KeyedStanzasType> deleteItem;

	public List<KeyedStanzasType> getDeleteItem() {
		if (this.deleteItem == null) {
			this.deleteItem = new ArrayList();
		}
		return this.deleteItem;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\framework\cds\DeleteResponse.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */