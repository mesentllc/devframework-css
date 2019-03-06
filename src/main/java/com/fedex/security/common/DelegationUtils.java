package com.fedex.security.common;

public class DelegationUtils {
	public static String[] parseDelegationResponse(String delegationInfo) {
		String[] splitDelegationResponse = new String[0];
		if (delegationInfo != null) {
			String[] tmpDelegationRespSplit = delegationInfo.split(",");
			splitDelegationResponse = new String[tmpDelegationRespSplit.length / 4];
			for (int i = 0; i < splitDelegationResponse.length; i++) {
				String indivDelSet = tmpDelegationRespSplit[(i * 4)] + "," + tmpDelegationRespSplit[(i * 4 + 1)] + "," + tmpDelegationRespSplit[(i * 4 + 2)] + "," + tmpDelegationRespSplit[(i * 4 + 3)];
				splitDelegationResponse[i] = indivDelSet;
			}
		}
		return splitDelegationResponse;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\common\DelegationUtils.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */