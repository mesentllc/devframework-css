package com.fedex.enterprise.security.utils;

public class LDAPUserRecord {
	private static final long serialVersionUID = 1L;
	protected String uid;
	protected String firstName;
	protected String lastName;
	protected String nickName;
	protected boolean isHuman;
	protected boolean isApplication;
	protected String manager;
	protected String city;
	protected String countryCode;
	protected String fedExExpressRegion;
	protected String fedExOpCo;
	protected String jobCode;
	protected String managementLevel;
	protected String orgCode;
	protected String salesTerritory;
	protected String station;

	public void setUid(String uid) {
		this.uid = uid;
	}

	public String getUid() {
		return this.uid;
	}

	public String getFirstName() {
		return this.firstName;
	}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}

	public String getLastName() {
		return this.lastName;
	}

	public void setLastName(String lastName) {
		this.lastName = lastName;
	}

	public String getNickName() {
		if ((this.nickName != null) && (!this.nickName.isEmpty())) {
			return this.nickName;
		}
		return this.firstName;
	}

	public void setNickName(String nickName) {
		this.nickName = nickName;
	}

	public boolean isHuman() {
		return this.isHuman;
	}

	public void setHuman(boolean isHuman) {
		this.isHuman = isHuman;
		this.isApplication = !isHuman;
	}

	public boolean isApplication() {
		return this.isApplication;
	}

	public void setApplication(boolean isApplication) {
		this.isApplication = isApplication;
		this.isHuman = !isApplication;
	}

	public String toString() {
		return "LDAPUserRecord [firstName=" + this.firstName + ", isApplication=" + this.isApplication + ", isHuman=" + this.isHuman + ", lastName=" + this.lastName + ", nickName=" + this.nickName + ",manager=" + this.manager + ", uid=" + this.uid + "]";
	}

	public String getManager() {
		return this.manager;
	}

	public void setManager(String manager) {
		this.manager = manager;
	}

	public String getCity() {
		return this.city;
	}

	public void setCity(String city) {
		this.city = city;
	}

	public String getCountryCode() {
		return this.countryCode;
	}

	public void setCountryCode(String countryCode) {
		this.countryCode = countryCode;
	}

	public String getFedExExpressRegion() {
		return this.fedExExpressRegion;
	}

	public void setFedExExpressRegion(String fedExExpressRegion) {
		this.fedExExpressRegion = fedExExpressRegion;
	}

	public String getFedExOpCo() {
		return this.fedExOpCo;
	}

	public void setFedExOpCo(String fedExOpCo) {
		this.fedExOpCo = fedExOpCo;
	}

	public String getJobCode() {
		return this.jobCode;
	}

	public void setJobCode(String jobCode) {
		this.jobCode = jobCode;
	}

	public String getManagementLevel() {
		return this.managementLevel;
	}

	public void setManagementLevel(String managementLevel) {
		this.managementLevel = managementLevel;
	}

	public String getOrgCode() {
		return this.orgCode;
	}

	public void setOrgCode(String orgCode) {
		this.orgCode = orgCode;
	}

	public String getSalesTerritory() {
		return this.salesTerritory;
	}

	public void setSalesTerritory(String salesTerritory) {
		this.salesTerritory = salesTerritory;
	}

	public String getStation() {
		return this.station;
	}

	public void setStation(String station) {
		this.station = station;
	}
}
