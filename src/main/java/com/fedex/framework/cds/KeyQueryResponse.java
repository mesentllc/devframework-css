package com.fedex.framework.cds;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import java.util.ArrayList;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {"keyedStanzas"})
@XmlRootElement(name = "keyQueryResponse")
public class KeyQueryResponse {
	protected List<KeyedStanzasType> keyedStanzas;

	public List<KeyedStanzasType> getKeyedStanzas() {
		if (this.keyedStanzas == null) {
			this.keyedStanzas = new ArrayList();
		}
		return this.keyedStanzas;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\framework\cds\KeyQueryResponse.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */