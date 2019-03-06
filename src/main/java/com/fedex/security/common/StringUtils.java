package com.fedex.security.common;

public class StringUtils {
	public static boolean isNullOrBlank(String s) {
		boolean result = true;
		if ((s != null) && (s.trim().length() > 0)) {
			result = false;
		}
		return result;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\common\StringUtils.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */