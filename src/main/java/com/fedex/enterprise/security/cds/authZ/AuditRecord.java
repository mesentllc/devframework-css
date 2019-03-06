package com.fedex.enterprise.security.cds.authZ;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import javax.xml.datatype.XMLGregorianCalendar;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "")
@XmlRootElement(name = "auditRecord")
public class AuditRecord {
	@XmlAttribute(name = "DocumentId", required = true)
	protected long documentId;
	@XmlAttribute(name = "ImpactedStanza", required = true)
	protected String impactedStanza;
	@XmlAttribute(name = "AppOrRealm", required = true)
	protected String appOrRealm;
	@XmlAttribute(name = "EventType", required = true)
	protected String eventType;
	@XmlAttribute(name = "EventDesc", required = true)
	protected String eventDesc;
	@XmlAttribute(name = "ChangedBy", required = true)
	protected String changedBy;
	@XmlAttribute(name = "EventTmstp", required = true)
	protected XMLGregorianCalendar eventTmstp;
	@XmlAttribute(required = true)
	protected String domain;
	@XmlAttribute(required = true)
	protected int majorVersion;
	@XmlAttribute(required = true)
	protected int minorVersion;

	public long getDocumentId() {
		return this.documentId;
	}

	public void setDocumentId(long value) {
		this.documentId = value;
	}

	public String getImpactedStanza() {
		return this.impactedStanza;
	}

	public void setImpactedStanza(String value) {
		this.impactedStanza = value;
	}

	public String getAppOrRealm() {
		return this.appOrRealm;
	}

	public void setAppOrRealm(String value) {
		this.appOrRealm = value;
	}

	public String getEventType() {
		return this.eventType;
	}

	public void setEventType(String value) {
		this.eventType = value;
	}

	public String getEventDesc() {
		return this.eventDesc;
	}

	public void setEventDesc(String value) {
		this.eventDesc = value;
	}

	public String getChangedBy() {
		return this.changedBy;
	}

	public void setChangedBy(String value) {
		this.changedBy = value;
	}

	public XMLGregorianCalendar getEventTmstp() {
		return this.eventTmstp;
	}

	public void setEventTmstp(XMLGregorianCalendar value) {
		this.eventTmstp = value;
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
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\cds\authZ\AuditRecord.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */