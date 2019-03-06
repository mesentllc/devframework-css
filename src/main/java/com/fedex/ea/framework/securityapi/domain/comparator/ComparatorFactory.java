package com.fedex.ea.framework.securityapi.domain.comparator;

import com.fedex.enterprise.security.utils.SecurityDataBaseClass;

import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;

public class ComparatorFactory {
	private static final Map<String, Factory> FACTORY_MAP = Collections.unmodifiableMap(new HashMap() {
		private static final long serialVersionUID = 1L;
	});

	public static <T extends SecurityDataBaseClass> Comparator<T> createComparator(String compareType, boolean compareChildren) {
		Factory factory = FACTORY_MAP.get(compareType);
		if (factory == null) {
			throw new RuntimeException("Unable to create comparator, the ComparatorFactory class needs to be updated for " + compareType);
		}
		Comparator<T> comparator = (Comparator<T>)factory.create(compareChildren);
		if (comparator == null) {
			throw new RuntimeException("Unable to find comparator for " + compareType);
		}
		return comparator;
	}

	private interface Factory {
		Comparator<? extends SecurityDataBaseClass> create(boolean paramBoolean);
	}
}
