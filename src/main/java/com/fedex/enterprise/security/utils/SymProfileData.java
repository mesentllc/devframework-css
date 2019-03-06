package com.fedex.enterprise.security.utils;

import java.util.List;

public class SymProfileData {
	private String symProfileNm;
	private long symProfileId;
	private String profileITOwner;
	private String profileBusOwner;
	private List<SymAppData> symAppData;

	public String getSymProfileNm() {
		return this.symProfileNm;
	}

	public void setSymProfileNm(String symProfileNm) {
		this.symProfileNm = symProfileNm;
	}

	public long getSymProfileId() {
		return this.symProfileId;
	}

	public void setSymProfileId(long symProfileId) {
		this.symProfileId = symProfileId;
	}

	public String getProfileITOwner() {
		return this.profileITOwner;
	}

	public void setProfileITOwner(String profileITOwner) {
		this.profileITOwner = profileITOwner;
	}

	public String getProfileBusOwner() {
		return this.profileBusOwner;
	}

	public void setProfileBusOwner(String profileBusOwner) {
		this.profileBusOwner = profileBusOwner;
	}

	public List<SymAppData> getSymAppData() {
		return this.symAppData;
	}

	public void setSymAppData(List<SymAppData> symAppData) {
		this.symAppData = symAppData;
	}

	public String toString() {
		return "SymProfileData [profileBusOwner=" + this.profileBusOwner + ", profileITOwner=" + this.profileITOwner + ", symAppData=" + this.symAppData + ", symProfileId=" + this.symProfileId + ", symProfileNm=" + this.symProfileNm + "]";
	}
}
