package com.fedex.ea.framework.securityapi.domain.comparator;

import com.fedex.enterprise.security.role.restriction.RestrictionDataItem;

import java.io.Serializable;
import java.util.Comparator;

public class RestrictionDataItemComparator
		extends SecurityDataBaseComparator
		implements Serializable, Comparator<RestrictionDataItem> {
	private static final long serialVersionUID = 1L;

	public RestrictionDataItemComparator() {
	}

	public RestrictionDataItemComparator(boolean compareChildren) {
		super(compareChildren);
	}

	public int compare(RestrictionDataItem o1, RestrictionDataItem o2) {
		int ret = 0;
		ret = compareLists(o1.getEntryList(), o2.getEntryList(), new RestrictionEntryComparator(), ret);
		return ret;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\domain\comparator\RestrictionDataItemComparator.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */