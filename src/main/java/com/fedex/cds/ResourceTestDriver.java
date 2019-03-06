package com.fedex.cds;

import com.fedex.security.client.ClientCipherProviderFactory;
import com.fedex.security.client.KeystoreCipherProviderImpl;
import com.fedex.security.client.PkcTokenGeneratorImpl;

public class ResourceTestDriver {
	static {
		ClientCipherProviderFactory.configure(KeystoreCipherProviderImpl.getInstance());
		PkcTokenGeneratorImpl.getInstance().configure();
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\cds\ResourceTestDriver.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */