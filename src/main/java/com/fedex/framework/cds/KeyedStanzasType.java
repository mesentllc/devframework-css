package com.fedex.framework.cds;

import org.w3c.dom.Element;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAnyElement;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.datatype.XMLGregorianCalendar;
import java.util.ArrayList;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "keyedStanzasType", propOrder = {"key", "stanza", "changeContext"})
public class KeyedStanzasType {
	protected long key;
	@XmlElement(required = true)
	protected List<Stanza> stanza;
	protected ChangeContextType changeContext;

	public long getKey() {
		return this.key;
	}

	public void setKey(long value) {
		this.key = value;
	}

	public List<Stanza> getStanza() {
		if (this.stanza == null) {
			this.stanza = new ArrayList();
		}
		return this.stanza;
	}

	public ChangeContextType getChangeContext() {
		return this.changeContext;
	}

	public void setChangeContext(ChangeContextType value) {
		this.changeContext = value;
	}

	@XmlAccessorType(XmlAccessType.FIELD)
	@XmlType(name = "", propOrder = {"domain", "name", "version", "any", "lastUpdate", "optimisticLockToken"})
	public static class Stanza {
		@XmlElement(required = true)
		protected String domain;
		@XmlElement(required = true)
		protected String name;
		@XmlElement(required = true)
		protected String version;
		@XmlAnyElement
		protected Element any;
		@XmlSchemaType(name = "dateTime")
		protected XMLGregorianCalendar lastUpdate;
		protected int optimisticLockToken;

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

		public String getVersion() {
			return this.version;
		}

		public void setVersion(String value) {
			this.version = value;
		}

		public Element getAny() {
			return this.any;
		}

		public void setAny(Element value) {
			this.any = value;
		}

		public XMLGregorianCalendar getLastUpdate() {
			return this.lastUpdate;
		}

		public void setLastUpdate(XMLGregorianCalendar value) {
			this.lastUpdate = value;
		}

		public int getOptimisticLockToken() {
			return this.optimisticLockToken;
		}

		public void setOptimisticLockToken(int value) {
			this.optimisticLockToken = value;
		}
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\framework\cds\KeyedStanzasType.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */