package com.fedex.ea.framework.securityapi.domain.comparator;

import com.fedex.enterprise.security.resource.ResourceData;

import java.io.Serializable;
import java.util.Comparator;

public class ResourceDataContentComparator
		extends SecurityDataBaseComparator
		implements Serializable, Comparator<ResourceData> {
	private static final long serialVersionUID = 1L;

	public ResourceDataContentComparator() {
	}

	public ResourceDataContentComparator(boolean compareChildren) {
		super(compareChildren);
	}

	public int compare(ResourceData o1, ResourceData o2) {
		int ret = 0;
		String name1 = ResourceUserKeyComparator.cleanResourceName(o1.getResName());
		String name2 = ResourceUserKeyComparator.cleanResourceName(o2.getResName());
		ret = compare(name1, name2, ret);
		ret = compare(o1.getResDesc(), o2.getResDesc(), ret);
		return ret;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\domain\comparator\ResourceDataContentComparator.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */