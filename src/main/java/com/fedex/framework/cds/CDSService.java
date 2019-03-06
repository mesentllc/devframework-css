package com.fedex.framework.cds;

import javax.xml.namespace.QName;
import javax.xml.ws.Service;
import javax.xml.ws.WebEndpoint;
import javax.xml.ws.WebServiceClient;
import javax.xml.ws.WebServiceFeature;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.logging.Logger;

@WebServiceClient(name = "CDSService", targetNamespace = "http://www.fedex.com/xmlns/cds2/ws", wsdlLocation = "file:/C:/Java/ESC-4.3.1/DeveloperFramework/SecurityAPI/cds2.wsdl")
public class CDSService
		extends Service {
	private static final URL CDSSERVICE_WSDL_LOCATION;
	private static final Logger logger = Logger.getLogger(CDSService.class.getName());

	static {
		URL url = null;
		try {
			URL baseUrl = CDSService.class.getResource(".");
			url = new URL(baseUrl, "file:/C:/Java/ESC-4.3.1/DeveloperFramework/SecurityAPI/cds2.wsdl");
		}
		catch (MalformedURLException e) {
			logger.warning("Failed to create URL for the wsdl Location: 'file:/C:/Java/ESC-4.3.1/DeveloperFramework/SecurityAPI/cds2.wsdl', retrying as a local file");
			logger.warning(e.getMessage());
		}
		CDSSERVICE_WSDL_LOCATION = url;
	}

	public CDSService(URL wsdlLocation, QName serviceName) {
		super(wsdlLocation, serviceName);
	}

	public CDSService() {
		super(CDSSERVICE_WSDL_LOCATION, new QName("http://www.fedex.com/xmlns/cds2/ws", "CDSService"));
	}

	@WebEndpoint(name = "CDSSoap11")
	public CDS getCDSSoap11() {
		return super.getPort(new QName("http://www.fedex.com/xmlns/cds2/ws", "CDSSoap11"), CDS.class);
	}

	@WebEndpoint(name = "CDSSoap11")
	public CDS getCDSSoap11(WebServiceFeature... features) {
		return super.getPort(new QName("http://www.fedex.com/xmlns/cds2/ws", "CDSSoap11"), CDS.class, features);
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\framework\cds\CDSService.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */