package com.fedex.security.utils;

import java.util.Properties;

public class SecurityUtils {
	public static void trimProperties(Properties props) {
		if (props != null) {
			for (java.util.Map.Entry<Object, Object> es : props.entrySet()) {
				Object value = es.getValue();
				if (value != null) {
					es.setValue(value.toString().trim());
				}
			}
		}
	}
}
