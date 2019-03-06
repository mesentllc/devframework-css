package com.fedex.ea.framework.securityapi.domain.comparator;

import com.fedex.enterprise.security.role.GroupRoleData;

import java.io.Serializable;
import java.util.Comparator;

public class GroupRoleDataContentComparator
		extends SecurityDataBaseComparator
		implements Serializable, Comparator<GroupRoleData> {
	private static final long serialVersionUID = 1L;

	public GroupRoleDataContentComparator() {
	}

	public GroupRoleDataContentComparator(boolean compareChildren) {
		super(compareChildren);
	}

	public int compare(GroupRoleData o1, GroupRoleData o2) {
		int ret = 0;
		ret = compare(o1.getGroupNm(), o2.getGroupNm(), ret);
		return ret;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\domain\comparator\GroupRoleDataContentComparator.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */