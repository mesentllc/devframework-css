package com.fedex.xmlns.cds.authz;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import java.util.ArrayList;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {"restrictionItem", "appid", "rolename", "userid", "roledocid"})
@XmlRootElement(name = "restriction")
public class Restriction {
	@XmlElement(required = true)
	protected List<RestrictionItem> restrictionItem;
	@XmlElement(name = "APPID")
	protected long appid;
	@XmlElement(name = "ROLENAME", required = true)
	protected String rolename;
	@XmlElement(name = "USERID", required = true)
	protected USERID userid;
	@XmlElement(name = "ROLEDOCID")
	protected long roledocid;
	@XmlAttribute(required = true)
	protected String domain;
	@XmlAttribute(required = true)
	protected int majorVersion;
	@XmlAttribute(required = true)
	protected int minorVersion;

	public List<RestrictionItem> getRestrictionItem() {
		if (this.restrictionItem == null) {
			this.restrictionItem = new ArrayList();
		}
		return this.restrictionItem;
	}

	public long getAPPID() {
		return this.appid;
	}

	public void setAPPID(long value) {
		this.appid = value;
	}

	public String getROLENAME() {
		return this.rolename;
	}

	public void setROLENAME(String value) {
		this.rolename = value;
	}

	public USERID getUSERID() {
		return this.userid;
	}

	public void setUSERID(USERID value) {
		this.userid = value;
	}

	public long getROLEDOCID() {
		return this.roledocid;
	}

	public void setROLEDOCID(long value) {
		this.roledocid = value;
	}

	public String getDomain() {
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

	@XmlAccessorType(XmlAccessType.FIELD)
	@XmlType(name = "", propOrder = {"entry", "restrictionDataItemIndex"})
	public static class RestrictionItem {
		@XmlElement(required = true)
		protected List<Entry> entry;
		@XmlElement(required = true)
		protected String restrictionDataItemIndex;

		public List<Entry> getEntry() {
			if (this.entry == null) {
				this.entry = new ArrayList();
			}
			return this.entry;
		}

		public String getRestrictionDataItemIndex() {
			return this.restrictionDataItemIndex;
		}

		public void setRestrictionDataItemIndex(String value) {
			this.restrictionDataItemIndex = value;
		}

		@XmlAccessorType(XmlAccessType.FIELD)
		@XmlType(name = "", propOrder = {"key", "value"})
		public static class Entry {
			@XmlElement(required = true)
			protected String key;
			@XmlElement(required = true)
			protected String value;

			public String getKey() {
				return this.key;
			}

			public void setKey(String value) {
				this.key = value;
			}

			public String getValue() {
				return this.value;
			}

			public void setValue(String value) {
				this.value = value;
			}
		}
	}

	@XmlAccessorType(XmlAccessType.FIELD)
	@XmlType(name = "", propOrder = {"groupName", "employeeId"})
	public static class USERID {
		protected String groupName;
		protected String employeeId;

		public String getGroupName() {
			return this.groupName;
		}

		public void setGroupName(String value) {
			this.groupName = value;
		}

		public String getEmployeeId() {
			return this.employeeId;
		}

		public void setEmployeeId(String value) {
			this.employeeId = value;
		}
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\xmlns\cds\authz\Restriction.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */