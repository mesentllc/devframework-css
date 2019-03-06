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
@XmlType(name = "", propOrder = {"restoreItem"})
@XmlRootElement(name = "restoreRequest")
public class RestoreRequest {
	@XmlElement(required = true)
	protected List<RestoreItem> restoreItem;

	public List<RestoreItem> getRestoreItem() {
		if (this.restoreItem == null) {
			this.restoreItem = new ArrayList();
		}
		return this.restoreItem;
	}

	@XmlAccessorType(XmlAccessType.FIELD)
	@XmlType(name = "", propOrder = {"key", "stanzaId", "sequenceCounter", "changeContext"})
	public static class RestoreItem {
		protected long key;
		@XmlElement(required = true)
		protected StanzaId stanzaId;
		protected int sequenceCounter;
		protected ChangeContextType changeContext;
		@XmlAttribute
		protected Boolean skipUpdateNotifications;

		public long getKey() {
			return this.key;
		}

		public void setKey(long value) {
			this.key = value;
		}

		public StanzaId getStanzaId() {
			return this.stanzaId;
		}

		public void setStanzaId(StanzaId value) {
			this.stanzaId = value;
		}

		public int getSequenceCounter() {
			return this.sequenceCounter;
		}

		public void setSequenceCounter(int value) {
			this.sequenceCounter = value;
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
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\framework\cds\RestoreRequest.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */