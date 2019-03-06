package com.fedex.security.server;

public class Permission {
	private String resource = null;
	private String action = null;
	private int hashCode = -1;

	public Permission(String resource, String action) {
		this.resource = resource;
		this.action = action;
		setHashCode();
	}

	public String getResource() {
		return this.resource;
	}

	public void setResource(String resource) {
		this.resource = resource;
		setHashCode();
	}

	public String getAction() {
		return this.action;
	}

	public void setAction(String action) {
		this.action = action;
		setHashCode();
	}

	private void setHashCode() {
		String temp = "";
		if (this.resource != null) {
			temp = temp + this.resource;
		}
		if (this.action != null) {
			temp = temp + this.action;
		}
		this.hashCode = temp.hashCode();
	}

	public int hashCode() {
		return this.hashCode;
	}

	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		return ((o instanceof Permission)) && (this.resource != null) && (this.action != null) && (this.resource.equals(((Permission)o).getResource())) && (this.action.equals(((Permission)o).getAction()));
	}

	public String toString() {
		return this.resource + " " + this.action;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\server\Permission.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */