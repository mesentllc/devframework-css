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
@XmlType(name = "", propOrder = {"modifyItem"})
@XmlRootElement(name = "modifyRequest")
public class ModifyRequest {
	@XmlElement(required = true)
	protected List<ModifyItem> modifyItem;

	public List<ModifyItem> getModifyItem() {
		if (this.modifyItem == null) {
			this.modifyItem = new ArrayList();
		}
		return this.modifyItem;
	}

	@XmlAccessorType(XmlAccessType.FIELD)
	@XmlType(name = "", propOrder = {"keyAndLock", "stanzaId", "action", "changeContext"})
	public static class ModifyItem {
		@XmlElement(required = true)
		protected List<KeyAndLock> keyAndLock;
		@XmlElement(required = true)
		protected StanzaIdType stanzaId;
		protected List<Action> action;
		protected ChangeContextType changeContext;
		@XmlAttribute
		protected Boolean skipUpdateNotifications;

		public List<KeyAndLock> getKeyAndLock() {
			if (this.keyAndLock == null) {
				this.keyAndLock = new ArrayList();
			}
			return this.keyAndLock;
		}

		public StanzaIdType getStanzaId() {
			return this.stanzaId;
		}

		public void setStanzaId(StanzaIdType value) {
			this.stanzaId = value;
		}

		public List<Action> getAction() {
			if (this.action == null) {
				this.action = new ArrayList();
			}
			return this.action;
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
		@XmlType(name = "", propOrder = {"add", "change", "remove"})
		public static class Action {
			protected Add add;
			protected Change change;
			protected Remove remove;

			public Add getAdd() {
				return this.add;
			}

			public void setAdd(Add value) {
				this.add = value;
			}

			public Change getChange() {
				return this.change;
			}

			public void setChange(Change value) {
				this.change = value;
			}

			public Remove getRemove() {
				return this.remove;
			}

			public void setRemove(Remove value) {
				this.remove = value;
			}

			@XmlAccessorType(XmlAccessType.FIELD)
			@XmlType(name = "", propOrder = {"xpath", "value", "xmlValue", "beforeXpath"})
			public static class Add {
				@XmlElement(required = true)
				protected String xpath;
				protected String value;
				protected XmlValue xmlValue;
				protected String beforeXpath;

				public String getXpath() {
					return this.xpath;
				}

				public void setXpath(String value) {
					this.xpath = value;
				}

				public String getValue() {
					return this.value;
				}

				public void setValue(String value) {
					this.value = value;
				}

				public XmlValue getXmlValue() {
					return this.xmlValue;
				}

				public void setXmlValue(XmlValue value) {
					this.xmlValue = value;
				}

				public String getBeforeXpath() {
					return this.beforeXpath;
				}

				public void setBeforeXpath(String value) {
					this.beforeXpath = value;
				}

				@XmlAccessorType(XmlAccessType.FIELD)
				@XmlType(name = "", propOrder = {"any"})
				public static class XmlValue {
					@XmlAnyElement
					protected Element any;

					public Element getAny() {
						return this.any;
					}

					public void setAny(Element value) {
						this.any = value;
					}
				}
			}

			@XmlAccessorType(XmlAccessType.FIELD)
			@XmlType(name = "", propOrder = {"xpath", "value", "xmlValue"})
			public static class Change {
				@XmlElement(required = true)
				protected String xpath;
				protected String value;
				protected XmlValue xmlValue;

				public String getXpath() {
					return this.xpath;
				}

				public void setXpath(String value) {
					this.xpath = value;
				}

				public String getValue() {
					return this.value;
				}

				public void setValue(String value) {
					this.value = value;
				}

				public XmlValue getXmlValue() {
					return this.xmlValue;
				}

				public void setXmlValue(XmlValue value) {
					this.xmlValue = value;
				}

				@XmlAccessorType(XmlAccessType.FIELD)
				@XmlType(name = "", propOrder = {"any"})
				public static class XmlValue {
					@XmlAnyElement
					protected Element any;

					public Element getAny() {
						return this.any;
					}

					public void setAny(Element value) {
						this.any = value;
					}
				}
			}

			@XmlAccessorType(XmlAccessType.FIELD)
			@XmlType(name = "", propOrder = {"xpath"})
			public static class Remove {
				@XmlElement(required = true)
				protected String xpath;

				public String getXpath() {
					return this.xpath;
				}

				public void setXpath(String value) {
					this.xpath = value;
				}
			}
		}

		@XmlAccessorType(XmlAccessType.FIELD)
		@XmlType(name = "", propOrder = {"key", "optimisticLockToken"})
		public static class KeyAndLock {
			protected long key;
			protected Integer optimisticLockToken;

			public long getKey() {
				return this.key;
			}

			public void setKey(long value) {
				this.key = value;
			}

			public Integer getOptimisticLockToken() {
				return this.optimisticLockToken;
			}

			public void setOptimisticLockToken(Integer value) {
				this.optimisticLockToken = value;
			}
		}
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\framework\cds\ModifyRequest.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */