package com.fedex.idm.delegation.webservice;

import javax.xml.namespace.QName;
import javax.xml.ws.Service;
import javax.xml.ws.WebEndpoint;
import javax.xml.ws.WebServiceClient;
import javax.xml.ws.WebServiceFeature;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.logging.Logger;

@WebServiceClient(name = "DelegationV2", targetNamespace = "http://delegationv2.idm.fedex.com/", wsdlLocation = "http://idmtest02.infosec.fedex.com:4388/DelegationJWS/DelegationV2?WSDL")
public class DelegationV2
		extends Service {
	private static final URL DELEGATIONV2_WSDL_LOCATION;
	private static final Logger logger = Logger.getLogger(DelegationV2.class.getName());

	static {
		URL url = null;
		try {
			URL baseUrl = DelegationV2.class.getResource(".");
			url = new URL(baseUrl, "http://idmtest02.infosec.fedex.com:4388/DelegationJWS/DelegationV2?WSDL");
		}
		catch (MalformedURLException e) {
			logger.warning("Failed to create URL for the wsdl Location: 'http://idmtest02.infosec.fedex.com:4388/DelegationJWS/DelegationV2?WSDL', retrying as a local file");
			logger.warning(e.getMessage());
		}
		DELEGATIONV2_WSDL_LOCATION = url;
	}

	public DelegationV2(URL wsdlLocation, QName serviceName) {
		super(wsdlLocation, serviceName);
	}

	public DelegationV2() {
		super(DELEGATIONV2_WSDL_LOCATION, new QName("http://delegationv2.idm.fedex.com/", "DelegationV2"));
	}

	@WebEndpoint(name = "DelegationPortTypePort")
	public DelegationPortType getDelegationPortTypePort() {
		return super.getPort(new QName("http://delegationv2.idm.fedex.com/", "DelegationPortTypePort"), DelegationPortType.class);
	}

	@WebEndpoint(name = "DelegationPortTypePort")
	public DelegationPortType getDelegationPortTypePort(WebServiceFeature... features) {
		return super.getPort(new QName("http://delegationv2.idm.fedex.com/", "DelegationPortTypePort"), DelegationPortType.class, features);
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\idm\delegation\webservice\DelegationV2.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */