package com.fedex.enterprise.security.resource;

public class ResourceUtils {
	private static final String DELIMITER = "-";

	public static boolean getRootFlg(ResourceData resourceData) {
		boolean rootFlg = false;
		if (((resourceData.getResName().endsWith("-")) && (countOccurrences(resourceData.getResName()) == 1)) || (countOccurrences(resourceData.getResName()) == 0)) {
			rootFlg = true;
		}
		return rootFlg;
	}

	public static int countOccurrences(String resourceNm) {
		int count = 0;
		for (int i = 0; i < resourceNm.length(); i++) {
			if (resourceNm.charAt(i) == '-') {
				count++;
			}
		}
		return count;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\resource\ResourceUtils.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */