package com.fedex.ea.framework.securityapi.domain.comparator;

import com.fedex.enterprise.security.role.RoleData;

import java.io.Serializable;
import java.util.Comparator;

public class RoleDataContentComparator
		extends SecurityDataBaseComparator
		implements Serializable, Comparator<RoleData> {
	private static final long serialVersionUID = 1L;

	public RoleDataContentComparator() {
	}

	public RoleDataContentComparator(boolean compareChildren) {
		super(compareChildren);
	}

	public int compare(RoleData o1, RoleData o2) {
		int ret = 0;
		ret = compare(o1.getRoleNm(), o2.getRoleNm(), ret);
		ret = compare(o1.getRoleDesc(), o2.getRoleDesc(), ret);
		if ((ret == 0) && (isCompareChildren())) {
			ret = compareLists(o1.getAppMemberList(), o2.getAppMemberList(), SingletonComparatorFactory.createComparator("AppRoleUserKey", false), SingletonComparatorFactory.createComparator("AppRoleDataContent", true), ret);
			ret = compareLists(o1.getGroupMemberList(), o2.getGroupMemberList(), SingletonComparatorFactory.createComparator("GroupRoleUserKey", false), SingletonComparatorFactory.createComparator("GroupRoleDataContent", true), ret);
			ret = compareLists(o1.getUserMemberList(), o2.getUserMemberList(), SingletonComparatorFactory.createComparator("UserRoleUserKey", false), SingletonComparatorFactory.createComparator("UserRoleDataContent", true), ret);
			ret = compareLists(o1.getRestrictionMemberList(), o2.getRestrictionMemberList(), SingletonComparatorFactory.createComparator("RestrictionUserKey", false), SingletonComparatorFactory.createComparator("RestrictionDataContent", true), ret);
		}
		return ret;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\domain\comparator\RoleDataContentComparator.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */