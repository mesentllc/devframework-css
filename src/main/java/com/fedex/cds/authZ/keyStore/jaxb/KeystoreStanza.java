package com.fedex.cds.authZ.keyStore.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import javax.xml.datatype.XMLGregorianCalendar;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {"applicationId", "keystore", "passphrase", "expirationDateTime"})
@XmlRootElement(name = "keystoreStanza")
public class KeystoreStanza {
	protected long applicationId;
	@XmlElement(required = true)
	protected String keystore;
	@XmlElement(required = true)
	protected String passphrase;
	@XmlElement(required = true)
	protected XMLGregorianCalendar expirationDateTime;
	@XmlAttribute(required = true)
	protected String domain;
	@XmlAttribute(required = true)
	protected int majorVersion;
	@XmlAttribute(required = true)
	protected int minorVersion;

	public long getApplicationId() {
		return this.applicationId;
	}

	public void setApplicationId(long value) {
		this.applicationId = value;
	}

	public String getKeystore() {
		return this.keystore;
	}

	public void setKeystore(String value) {
		this.keystore = value;
	}

	public String getPassphrase() {
		return this.passphrase;
	}

	public void setPassphrase(String value) {
		this.passphrase = value;
	}

	public XMLGregorianCalendar getExpirationDateTime() {
		return this.expirationDateTime;
	}

	public void setExpirationDateTime(XMLGregorianCalendar value) {
		this.expirationDateTime = value;
	}

	public String getDomain() {
		if (this.domain == null) {
			return "authZ";
		}
		return this.domain;
	}

	public void setDomain(String value) {
		this.domain = value;
	}

	public int getMajorVersion() {
		return this.majorVersion;
	}

	public void setMajorVersion(int value) {
		this.majorVersion = value;
	}

	public int getMinorVersion() {
		return this.minorVersion;
	}

	public void setMinorVersion(int value) {
		this.minorVersion = value;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\cds\authZ\keyStore\jaxb\KeystoreStanza.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */