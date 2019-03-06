package com.fedex.ea.framework.securityapi.domain.comparator;

import com.fedex.enterprise.security.role.RoleData;

import java.io.Serializable;
import java.util.Comparator;

public class RoleUserKeyComparator
		extends SecurityDataBaseComparator
		implements Serializable, Comparator<RoleData> {
	private static final long serialVersionUID = 1L;

	public RoleUserKeyComparator() {
	}

	public RoleUserKeyComparator(boolean compareChildren) {
		super(compareChildren);
	}

	public int compare(RoleData o1, RoleData o2) {
		int ret = 0;
		ret = compare(o1.getRoleNm(), o2.getRoleNm(), ret);
		return ret;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\domain\comparator\RoleUserKeyComparator.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */