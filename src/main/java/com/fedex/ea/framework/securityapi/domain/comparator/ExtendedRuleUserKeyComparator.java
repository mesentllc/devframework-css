package com.fedex.ea.framework.securityapi.domain.comparator;

import com.fedex.enterprise.security.rule.ExtendedRuleData;

import java.io.Serializable;
import java.util.Comparator;

public class ExtendedRuleUserKeyComparator
		extends SecurityDataBaseComparator
		implements Serializable, Comparator<ExtendedRuleData> {
	private static final long serialVersionUID = 1L;

	public ExtendedRuleUserKeyComparator() {
	}

	public ExtendedRuleUserKeyComparator(boolean compareChildren) {
		super(compareChildren);
	}

	public int compare(ExtendedRuleData o1, ExtendedRuleData o2) {
		int ret = 0;
		ret = compare(o1.getExtRuleKey(), o2.getExtRuleKey(), ret);
		ret = compare(o1.getExtRuleOperator(), o2.getExtRuleOperator(), ret);
		ret = compare(o1.getExtRuleValue(), o2.getExtRuleValue(), ret);
		return ret;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\domain\comparator\ExtendedRuleUserKeyComparator.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */