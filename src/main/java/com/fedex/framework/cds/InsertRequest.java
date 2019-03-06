package com.fedex.framework.cds;

import org.w3c.dom.Element;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAnyElement;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import java.util.ArrayList;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {"insertItem"})
@XmlRootElement(name = "insertRequest")
public class InsertRequest {
	@XmlElement(required = true)
	protected List<InsertItem> insertItem;

	public List<InsertItem> getInsertItem() {
		if (this.insertItem == null) {
			this.insertItem = new ArrayList();
		}
		return this.insertItem;
	}

	@XmlAccessorType(XmlAccessType.FIELD)
	@XmlType(name = "", propOrder = {"any", "changeContext"})
	public static class InsertItem {
		@XmlAnyElement
		protected List<Element> any;
		protected ChangeContextType changeContext;
		@XmlAttribute
		protected Boolean skipUpdateNotifications;

		public List<Element> getAny() {
			if (this.any == null) {
				this.any = new ArrayList();
			}
			return this.any;
		}

		public ChangeContextType getChangeContext() {
			return this.changeContext;
		}

		public void setChangeContext(ChangeContextType value) {
			this.changeContext = value;
		}

		public Boolean isSkipUpdateNotifications() {
			return this.skipUpdateNotifications;
		}

		public void setSkipUpdateNotifications(Boolean value) {
			this.skipUpdateNotifications = value;
		}
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\framework\cds\InsertRequest.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */