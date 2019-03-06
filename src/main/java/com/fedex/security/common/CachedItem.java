package com.fedex.security.common;

public class CachedItem {
	private final Object payload;
	private final long createTime;
	private final long ttl;
	private boolean expiring = true;

	public CachedItem(Object payload) {
		this.createTime = System.currentTimeMillis();
		this.payload = payload;
		this.expiring = false;
		this.ttl = 0L;
	}

	public CachedItem(Object payload, long ttl) {
		this.createTime = System.currentTimeMillis();
		this.payload = payload;
		this.expiring = true;
		this.ttl = ttl;
	}

	public Object getPayload() {
		return this.payload;
	}

	public long getTtl() {
		return this.ttl;
	}

	public long getCreateTime() {
		return this.createTime;
	}

	public boolean isExpired() {
		return (this.expiring) && (this.createTime + this.ttl < System.currentTimeMillis());
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\common\CachedItem.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */