package com.fedex.security.client;

import com.fedex.framework.utility.FedExAnnotatedMBean;

import javax.management.NotCompliantMBeanException;
import java.util.Date;

public class KeystoreRotationMBean
		extends FedExAnnotatedMBean implements KeystoreRotationMBeanInterface {
	public KeystoreRotationMBean() throws NotCompliantMBeanException {
		super(KeystoreRotationMBeanInterface.class);
	}

	public String getCertExpirationDateAndTime() {
		Date certDate = KeystoreCipherProviderImpl.certExprDate;
		return certDate.toString();
	}

	public String triggerRotation() throws Exception {
		String result;
		try {
			result = KeystoreExpirationCheck.completeCertRotation();
		}
		catch (Exception ee) {
			throw new Exception("Unexpected rotation exception:" + ee.getMessage(), ee);
		}
		return result;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\client\KeystoreRotationMBean.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */