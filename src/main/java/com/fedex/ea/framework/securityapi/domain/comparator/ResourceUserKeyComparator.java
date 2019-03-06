package com.fedex.ea.framework.securityapi.domain.comparator;

import com.fedex.enterprise.security.resource.ResourceData;

import java.io.Serializable;
import java.util.Comparator;

public class ResourceUserKeyComparator
		extends SecurityDataBaseComparator
		implements Serializable, Comparator<ResourceData> {
	private static final long serialVersionUID = 1L;

	public ResourceUserKeyComparator() {
	}

	public ResourceUserKeyComparator(boolean compareChildren) {
		super(compareChildren);
	}

	public int compare(ResourceData o1, ResourceData o2) {
		int ret = 0;
		String name1 = cleanResourceName(o1.getResName());
		String name2 = cleanResourceName(o2.getResName());
		ret = compare(name1, name2, ret);
		return ret;
	}

	public static String cleanResourceName(String resName) {
		String name = resName == null ? "" : resName;
		if (name.endsWith("/")) {
			name = name.substring(0, name.length() - 1);
		}
		if (name.startsWith("/")) {
			name = name.substring(1);
		}
		return name;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\domain\comparator\ResourceUserKeyComparator.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */