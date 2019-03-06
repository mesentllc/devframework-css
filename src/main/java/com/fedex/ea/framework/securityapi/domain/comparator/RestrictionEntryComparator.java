package com.fedex.ea.framework.securityapi.domain.comparator;

import com.fedex.enterprise.security.role.restriction.Entry;

import java.io.Serializable;
import java.util.Comparator;

public class RestrictionEntryComparator
		extends SecurityDataBaseComparator
		implements Serializable, Comparator<Entry> {
	private static final long serialVersionUID = 1L;

	public RestrictionEntryComparator() {
	}

	public RestrictionEntryComparator(boolean compareChildren) {
		super(compareChildren);
	}

	public int compare(Entry o1, Entry o2) {
		int ret = 0;
		ret = compare(o1.getKey(), o2.getKey(), ret);
		ret = compare(o1.getValue(), o2.getValue(), ret);
		return ret;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\domain\comparator\RestrictionEntryComparator.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */