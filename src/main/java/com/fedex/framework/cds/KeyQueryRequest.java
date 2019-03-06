package com.fedex.framework.cds;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import java.util.ArrayList;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {"name", "key", "stanzaId"})
@XmlRootElement(name = "keyQueryRequest")
public class KeyQueryRequest {
	protected String name;
	@XmlElement(required = true)
	protected List<String> key;
	@XmlElement(required = true)
	protected List<StanzaId> stanzaId;

	public String getName() {
		return this.name;
	}

	public void setName(String value) {
		this.name = value;
	}

	public List<String> getKey() {
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

	@XmlAccessorType(XmlAccessType.FIELD)
	@XmlType(name = "", propOrder = {"domain", "name", "version"})
	public static class StanzaId {
		@XmlElement(required = true)
		protected String domain;
		protected String name;
		protected String version;

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
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\framework\cds\KeyQueryRequest.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */