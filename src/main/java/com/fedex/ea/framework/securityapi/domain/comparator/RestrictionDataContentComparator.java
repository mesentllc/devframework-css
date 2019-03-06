package com.fedex.ea.framework.securityapi.domain.comparator;

import com.fedex.enterprise.security.role.restriction.RestrictionData;

import java.io.Serializable;
import java.util.Comparator;

public class RestrictionDataContentComparator
		extends SecurityDataBaseComparator
		implements Serializable, Comparator<RestrictionData> {
	private static final long serialVersionUID = 1L;

	public RestrictionDataContentComparator() {
	}

	public RestrictionDataContentComparator(boolean compareChildren) {
		super(compareChildren);
	}

	public int compare(RestrictionData o1, RestrictionData o2) {
		int ret = 0;
		ret = compare(o1.getEmplId(), o2.getEmplId(), ret);
		ret = compare(o1.getGroupNm(), o2.getGroupNm(), ret);
		ret = compare(o1.getRoleNm(), o2.getRoleNm(), ret);
		if ((ret == 0) && (isCompareChildren())) {
			ret = compareLists(o1.getRestrictionList(), o2.getRestrictionList(), new RestrictionDataItemComparator(), ret);
		}
		return ret;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\domain\comparator\RestrictionDataContentComparator.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */