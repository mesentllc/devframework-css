package com.fedex.ea.framework.securityapi.domain.comparator;

import com.fedex.enterprise.security.rule.RuleData;

import java.io.Serializable;
import java.util.Comparator;

public class RuleDataContentComparator
		extends SecurityDataBaseComparator
		implements Serializable, Comparator<RuleData> {
	private static final long serialVersionUID = 1L;

	public RuleDataContentComparator() {
	}

	public RuleDataContentComparator(boolean compareChildren) {
		super(compareChildren);
	}

	public int compare(RuleData o1, RuleData o2) {
		int ret = 0;
		String resource1 = o1.getResourceNm();
		String resource2 = o2.getResourceNm();
		if ((resource1 != null) && (resource1.endsWith("/"))) {
			resource1 = resource1.substring(0, resource1.length() - 1);
		}
		if ((resource2 != null) && (resource2.endsWith("/"))) {
			resource2 = resource2.substring(0, resource2.length() - 1);
		}
		ret = compare(o1.getActionNm(), o2.getActionNm(), ret);
		ret = compare(o1.getRoleNm(), o2.getRoleNm(), ret);
		ret = compare(resource1, resource2, ret);
		ret = compare(o1.getGrantFlg(), o2.getGrantFlg(), ret);
		if ((ret == 0) && (isCompareChildren())) {
			ret = compareLists(o1.getExtendedRuleList(), o2.getExtendedRuleList(), SingletonComparatorFactory.createComparator("ExtendedRuleUserKey", false), SingletonComparatorFactory.createComparator("ExtendedRuleDataContent", true), ret);
		}
		return ret;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\domain\comparator\RuleDataContentComparator.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */