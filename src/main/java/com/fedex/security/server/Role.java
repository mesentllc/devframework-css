package com.fedex.security.server;

import java.io.Serializable;
import java.util.Arrays;
import java.util.List;

public class Role
		implements Serializable {
	private static final long serialVersionUID = 1L;
	private List<String> groups = null;
	private List<String> uids = null;
	public static final String ANY_UID = "*";
	public static final Role ANYBODY = new Role(null, Arrays.asList("*"));

	public Role(List<String> groups, List<String> uids) {
		this.groups = groups;
		this.uids = uids;
	}

	public List<String> getGroups() {
		return this.groups;
	}

	public List<String> getUids() {
		return this.uids;
	}

	public String toString() {
		return "Groups: " + this.groups + " ----UIDs: " + this.uids;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\server\Role.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */