package com.fedex.ea.framework.securityapi.domain.comparator;

import com.fedex.enterprise.security.role.AppRoleData;

import java.io.Serializable;
import java.util.Comparator;

public class AppRoleUserKeyComparator
		extends SecurityDataBaseComparator
		implements Serializable, Comparator<AppRoleData> {
	private static final long serialVersionUID = 1L;

	public AppRoleUserKeyComparator() {
	}

	public AppRoleUserKeyComparator(boolean compareChildren) {
		super(compareChildren);
	}

	public int compare(AppRoleData o1, AppRoleData o2) {
		int ret = 0;
		String appId1 = o1.getAppId() == null ? "" : o1.getAppId();
		String appId2 = o2.getAppId() == null ? "" : o2.getAppId();
		if (appId1.startsWith("APP")) {
			appId1 = appId1.substring(3);
		}
		if (appId2.startsWith("APP")) {
			appId2 = appId2.substring(3);
		}
		ret = compare(appId1, appId2, ret);
		return ret;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\domain\comparator\AppRoleUserKeyComparator.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */