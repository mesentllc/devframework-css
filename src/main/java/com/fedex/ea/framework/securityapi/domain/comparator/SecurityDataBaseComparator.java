package com.fedex.ea.framework.securityapi.domain.comparator;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class SecurityDataBaseComparator {
	protected static final String EMPTY_STRING = "";
	protected static final String NA_STRING = "NA";
	private boolean compareChildren = false;

	public SecurityDataBaseComparator() {
	}

	public SecurityDataBaseComparator(boolean compareChildren) {
		this.compareChildren = compareChildren;
	}

	public static int compare(String str1, String str2, int previousResult) {
		int ret = 0;
		if (previousResult != 0) {
			ret = previousResult;
		}
		else {
			String modStr1 = str1 == null ? "" : str1;
			String modStr2 = str2 == null ? "" : str2;
			ret = modStr1.compareTo(modStr2);
		}
		return ret;
	}

	public static int compare(char c1, char c2, int previousResult) {
		int ret = 0;
		if (previousResult != 0) {
			ret = previousResult;
		}
		else {
			if (c1 != c2) {
				ret = c1 - c2;
			}
			else {
				ret = 0;
			}
		}
		return ret;
	}

	public static int compareNull(Object o1, Object o2) {
		int ret = 0;
		if (((o1 == null) && (o2 == null)) || ((o1 != null) && (o2 != null))) {
			ret = 0;
		}
		else {
			if ((o1 == null) && (o2 != null)) {
				ret = -1;
			}
			else {
				if ((o1 != null) && (o2 == null)) {
					ret = 1;
				}
			}
		}
		return ret;
	}

	public boolean isCompareChildren() {
		return this.compareChildren;
	}

	public static <T> int compareLists(List<T> list1, List<T> list2, Comparator<T> keyComparator, Comparator<T> contentComparator, int previousResult) {
		int ret = 0;
		if (previousResult != 0) {
			ret = previousResult;
		}
		else {
			if (((ret = compareNull(list1, list2)) == 0) && (list1 != null)) {
				if (list1.size() != list2.size()) {
					ret = list1.size() - list2.size();
				}
				else {
					ArrayList<T> newList1 = new ArrayList(list1);
					ArrayList<T> newList2 = new ArrayList(list1);
					Collections.sort(newList1, keyComparator);
					Collections.sort(newList2, keyComparator);
					for (int index = 0; index < newList2.size(); index++) {
						ret = contentComparator.compare(newList1.get(index), newList2.get(index));
						if (ret != 0) {
							break;
						}
					}
				}
			}
		}
		return ret;
	}

	public static <T> int compareLists(List<T> list1, List<T> list2, Comparator<T> comparator, int previousResult) {
		return compareLists(list1, list2, comparator, comparator, previousResult);
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\domain\comparator\SecurityDataBaseComparator.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */