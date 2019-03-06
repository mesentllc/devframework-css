package com.fedex.ea.framework.securityapi.domain.comparator;

import com.fedex.enterprise.security.utils.SecurityDataBaseClass;

import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;

public class SingletonComparatorFactory {
	private static Map<String, Comparator<?>> mapComparators = new HashMap();

	public static <T extends SecurityDataBaseClass> Comparator<T> createComparator(String compareType, boolean compareChildren) {
		String mapKey = compareType + (compareChildren ? "_T" : "_F");
		Comparator<T> comparator = null;
		if (mapComparators.containsKey(mapKey)) {
			comparator = (Comparator)mapComparators.get(mapKey);
		}
		else {
			comparator = ComparatorFactory.createComparator(compareType, compareChildren);
			mapComparators.put(mapKey, comparator);
		}
		return comparator;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\domain\comparator\SingletonComparatorFactory.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */