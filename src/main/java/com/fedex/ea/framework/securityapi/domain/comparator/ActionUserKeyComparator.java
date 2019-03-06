package com.fedex.ea.framework.securityapi.domain.comparator;

import com.fedex.enterprise.security.action.ActionData;

import java.io.Serializable;
import java.util.Comparator;

public class ActionUserKeyComparator
		extends SecurityDataBaseComparator
		implements Serializable, Comparator<ActionData> {
	private static final long serialVersionUID = 1L;

	public ActionUserKeyComparator() {
	}

	public ActionUserKeyComparator(boolean compareChildren) {
		super(compareChildren);
	}

	public int compare(ActionData o1, ActionData o2) {
		int ret = 0;
		ret = compare(o1.getActionNm(), o2.getActionNm(), ret);
		return ret;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\domain\comparator\ActionUserKeyComparator.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */