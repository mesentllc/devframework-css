package com.fedex.enterprise.security.customauthz;

import java.util.List;

public interface CustomAuthzService {
	CustomAuthzData getCustomAuthzByName(String paramString1, String paramString2);

	List<CustomAuthzData> getCustomAuthzForApplication(String paramString);

	long insertCustomAuthz(CustomAuthzData paramCustomAuthzData);

	void deleteCustomAuthz(CustomAuthzData paramCustomAuthzData);

	void updateCustomAuthz(CustomAuthzData paramCustomAuthzData);
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\customauthz\CustomAuthzService.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */