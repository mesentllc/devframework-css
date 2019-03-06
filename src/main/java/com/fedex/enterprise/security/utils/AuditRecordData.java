package com.fedex.enterprise.security.utils;

import java.sql.Timestamp;

public class AuditRecordData extends SecurityDataBaseClass implements java.io.Serializable {
	private static final long serialVersionUID = 1L;
	private String docKey;
	private Timestamp occurredTm;
	private String stanzaNm;
	private String eventTypeCd;
	private String eventDesc;
	private String updateBy;
	private String appOrRealm;
	private boolean selected;

	public enum ACTION {
		create,
		modify,
		view,
		manage,
		delete;

		ACTION() {
		}
	}

	public AuditRecordData() {
	}

	public AuditRecordData(String appid, String onBehalfOf, String desc, ACTION eventType, String stanza) {
		this.appOrRealm = appid;
		this.updateBy = onBehalfOf;
		this.stanzaNm = stanza;
		this.eventTypeCd = eventType.toString();
		this.eventDesc = desc;
	}

	public String toString() {
		return "AuditRecordData [appOrRealm=" + this.appOrRealm + ", docId=" + getDocId() + ", docKey=" + this.docKey + ", eventDesc=" + this.eventDesc + ", eventTypeCd=" + this.eventTypeCd + ", occurredTm=" + this.occurredTm + ", modifiedStanzaNm=" + this.stanzaNm + ", updateBy=" + this.updateBy + "]";
	}

	public String getDocKey() {
		return this.docKey;
	}

	public void setDocKey(String docKey) {
		this.docKey = docKey;
	}

	public String getEventTypeCd() {
		return this.eventTypeCd;
	}

	public void setEventTypeCd(ACTION eventTypeCd) {
		this.eventTypeCd = eventTypeCd.toString();
	}

	public String getEventDesc() {
		return this.eventDesc;
	}

	public void setEventDesc(String eventDesc) {
		this.eventDesc = eventDesc;
	}

	public String getUpdateBy() {
		return this.updateBy;
	}

	public void setUpdateBy(String updateBy) {
		this.updateBy = updateBy;
	}

	public String getStanzaNm() {
		return this.stanzaNm;
	}

	public void setStanzaNm(String stanzaNm) {
		this.stanzaNm = stanzaNm;
	}

	public Timestamp getOccurredTm() {
		return this.occurredTm;
	}

	public void setOccurredTm(Timestamp occurredTm) {
		this.occurredTm = occurredTm;
	}

	public String getAppOrRealm() {
		return this.appOrRealm;
	}

	public void setAppOrRealm(String appOrRealm) {
		this.appOrRealm = appOrRealm;
	}

	public boolean isSelected() {
		return this.selected;
	}

	public void setSelected(boolean selected) {
		this.selected = selected;
	}

	public boolean validate() {
		return true;
	}
}
