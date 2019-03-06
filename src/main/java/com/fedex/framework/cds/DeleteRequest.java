package com.fedex.framework.cds;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import java.util.ArrayList;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {"deleteItem"})
@XmlRootElement(name = "deleteRequest")
public class DeleteRequest {
	@XmlElement(required = true)
	protected List<DeleteItem> deleteItem;

	public List<DeleteItem> getDeleteItem() {
		if (this.deleteItem == null) {
			this.deleteItem = new ArrayList();
		}
		return this.deleteItem;
	}

	@XmlAccessorType(XmlAccessType.FIELD)
	@XmlType(name = "", propOrder = {"key", "stanzaId", "changeContext"})
	public static class DeleteItem {
		@XmlElement(type = Long.class)
		protected List<Long> key;
		@XmlElement(required = true)
		protected List<StanzaId> stanzaId;
		protected ChangeContextType changeContext;
		@XmlAttribute
		protected Boolean bulkDelete;
		@XmlAttribute
		protected Boolean skipUpdateNotifications;

		public List<Long> getKey() {
			if (this.key == null) {
				this.key = new ArrayList();
			}
			return this.key;
		}

		public List<StanzaId> getStanzaId() {
			if (this.stanzaId == null) {
				this.stanzaId = new ArrayList();
			}
			return this.stanzaId;
		}

		public ChangeContextType getChangeContext() {
			return this.changeContext;
		}

		public void setChangeContext(ChangeContextType value) {
			this.changeContext = value;
		}

		public Boolean isBulkDelete() {
			return this.bulkDelete;
		}

		public void setBulkDelete(Boolean value) {
			this.bulkDelete = value;
		}

		public Boolean isSkipUpdateNotifications() {
			return this.skipUpdateNotifications;
		}

		public void setSkipUpdateNotifications(Boolean value) {
			this.skipUpdateNotifications = value;
		}

		@XmlAccessorType(XmlAccessType.FIELD)
		@XmlType(name = "", propOrder = {"domain", "name"})
		public static class StanzaId {
			@XmlElement(required = true)
			protected String domain;
			@XmlElement(required = true)
			protected String name;

			public String getDomain() {
				return this.domain;
			}

			public void setDomain(String value) {
				this.domain = value;
			}

			public String getName() {
				return this.name;
			}

			public void setName(String value) {
				this.name = value;
			}
		}
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\framework\cds\DeleteRequest.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */