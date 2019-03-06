package com.fedex.ea.framework.securityapi.domain.comparator;

import java.io.Serializable;
import java.util.Comparator;

public class StringComparator
		extends SecurityDataBaseComparator
		implements Serializable, Comparator<String> {
	private static final long serialVersionUID = 1L;

	public StringComparator() {
	}

	public StringComparator(boolean compareChildren) {
		super(compareChildren);
	}

	public int compare(String o1, String o2) {
		int ret = 0;
		ret = compare(o1, o2, ret);
		return ret;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\domain\comparator\StringComparator.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */