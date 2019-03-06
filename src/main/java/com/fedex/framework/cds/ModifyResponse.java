package com.fedex.framework.cds;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import java.util.ArrayList;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {"modifyItem"})
@XmlRootElement(name = "modifyResponse")
public class ModifyResponse {
	@XmlElement(required = true)
	protected List<ModifyItem> modifyItem;

	public List<ModifyItem> getModifyItem() {
		if (this.modifyItem == null) {
			this.modifyItem = new ArrayList();
		}
		return this.modifyItem;
	}

	@XmlAccessorType(XmlAccessType.FIELD)
	@XmlType(name = "", propOrder = {"keyedStanzas"})
	public static class ModifyItem {
		protected List<KeyedStanzasType> keyedStanzas;

		public List<KeyedStanzasType> getKeyedStanzas() {
			if (this.keyedStanzas == null) {
				this.keyedStanzas = new ArrayList();
			}
			return this.keyedStanzas;
		}
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\framework\cds\ModifyResponse.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */