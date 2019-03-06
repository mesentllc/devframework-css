package com.fedex.security.client;

import com.fedex.framework.utility.Description;

public interface KeystoreRotationMBeanInterface {
	@Description("Get application certificate expire date & time")
	String getCertExpirationDateAndTime();

	@Description("Rotate the application certificate immediately")
	String triggerRotation()
			throws Exception;
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\client\KeystoreRotationMBeanInterface.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */