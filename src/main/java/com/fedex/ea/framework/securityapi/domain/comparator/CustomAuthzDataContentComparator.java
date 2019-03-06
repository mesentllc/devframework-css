package com.fedex.ea.framework.securityapi.domain.comparator;

import com.fedex.enterprise.security.customauthz.CustomAuthzData;

import java.io.Serializable;
import java.util.Comparator;

public class CustomAuthzDataContentComparator
		extends SecurityDataBaseComparator
		implements Serializable, Comparator<CustomAuthzData> {
	private static final long serialVersionUID = 1L;

	public CustomAuthzDataContentComparator() {
	}

	public CustomAuthzDataContentComparator(boolean compareChildren) {
		super(compareChildren);
	}

	public int compare(CustomAuthzData o1, CustomAuthzData o2) {
		int ret = 0;
		ret = compare(o1.getClassNm(), o2.getClassNm(), ret);
		String classDesc1 = (o1.getClassDesc() == null) || (o1.getClassDesc().isEmpty()) ? "NA" : o1.getClassDesc();
		String classDesc2 = (o2.getClassDesc() == null) || (o2.getClassDesc().isEmpty()) ? "NA" : o2.getClassDesc();
		ret = compare(classDesc1, classDesc2, ret);
		return ret;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\domain\comparator\CustomAuthzDataContentComparator.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */