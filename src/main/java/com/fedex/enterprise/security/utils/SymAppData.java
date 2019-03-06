package com.fedex.enterprise.security.utils;

public class SymAppData {
	private String appNm;
	private long appId;

	public SymAppData() {
	}

	public SymAppData(long appId, String appNm) {
		this.appId = appId;
		this.appNm = appNm;
	}

	public String getAppNm() {
		return this.appNm;
	}

	public void setAppNm(String appNm) {
		this.appNm = appNm;
	}

	public long getAppId() {
		return this.appId;
	}

	public void setAppId(long appId) {
		this.appId = appId;
	}

	public String toString() {
		return "SymAppData [appId=" + this.appId + ", appNm=" + this.appNm + "]";
	}
}
