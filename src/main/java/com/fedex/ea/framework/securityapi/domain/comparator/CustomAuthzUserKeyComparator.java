package com.fedex.ea.framework.securityapi.domain.comparator;

import com.fedex.enterprise.security.customauthz.CustomAuthzData;

import java.io.Serializable;
import java.util.Comparator;

public class CustomAuthzUserKeyComparator
		extends SecurityDataBaseComparator
		implements Serializable, Comparator<CustomAuthzData> {
	private static final long serialVersionUID = 1L;

	public CustomAuthzUserKeyComparator() {
	}

	public CustomAuthzUserKeyComparator(boolean compareChildren) {
		super(compareChildren);
	}

	public int compare(CustomAuthzData o1, CustomAuthzData o2) {
		int ret = 0;
		ret = compare(o1.getClassNm(), o2.getClassNm(), ret);
		return ret;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\domain\comparator\CustomAuthzUserKeyComparator.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */