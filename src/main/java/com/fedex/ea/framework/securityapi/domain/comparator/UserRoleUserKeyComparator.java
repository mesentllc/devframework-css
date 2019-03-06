package com.fedex.ea.framework.securityapi.domain.comparator;

import com.fedex.enterprise.security.role.UserRoleData;

import java.io.Serializable;
import java.util.Comparator;

public class UserRoleUserKeyComparator
		extends SecurityDataBaseComparator
		implements Serializable, Comparator<UserRoleData> {
	private static final long serialVersionUID = 1L;

	public UserRoleUserKeyComparator() {
	}

	public UserRoleUserKeyComparator(boolean compareChildren) {
		super(compareChildren);
	}

	public int compare(UserRoleData o1, UserRoleData o2) {
		int ret = 0;
		ret = compare(o1.getEmpNbr(), o2.getEmpNbr(), ret);
		return ret;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\domain\comparator\UserRoleUserKeyComparator.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */