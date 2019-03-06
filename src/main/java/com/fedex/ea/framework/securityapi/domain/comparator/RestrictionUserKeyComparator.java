package com.fedex.ea.framework.securityapi.domain.comparator;

import com.fedex.enterprise.security.role.restriction.RestrictionData;

import java.io.Serializable;
import java.util.Comparator;

public class RestrictionUserKeyComparator
		extends SecurityDataBaseComparator
		implements Serializable, Comparator<RestrictionData> {
	private static final long serialVersionUID = 1L;

	public RestrictionUserKeyComparator() {
	}

	public RestrictionUserKeyComparator(boolean compareChildren) {
		super(compareChildren);
	}

	public int compare(RestrictionData o1, RestrictionData o2) {
		int ret = 0;
		ret = compare(o1.getEmplId(), o2.getEmplId(), ret);
		ret = compare(o1.getGroupNm(), o2.getGroupNm(), ret);
		ret = compare(o1.getRoleNm(), o2.getRoleNm(), ret);
		return ret;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\domain\comparator\RestrictionUserKeyComparator.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */