package com.fedex.cds.client.security;

import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import com.fedex.security.client.ClientCipherProviderFactory;
import com.fedex.security.client.KeystoreCipherProviderImpl;
import com.fedex.security.client.PkcTokenGeneratorImpl;

import javax.xml.namespace.QName;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPHeader;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;
import java.util.Set;

public class SecurityJaxWsHandler implements SOAPHandler<SOAPMessageContext> {
	private static final String WSSE_PREFIX = "wsse";
	private static final String WSSE_URI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
	private static final String serviceAppId = "943415_cds";
	private static String employeeNumber;
	private final FedExLoggerInterface log = FedExLogger.getLogger(SecurityJaxWsHandler.class);

	static {
		ClientCipherProviderFactory.configure(KeystoreCipherProviderImpl.getInstance());
	}

	private static PkcTokenGeneratorImpl gen = PkcTokenGeneratorImpl.getInstance();

	public SecurityJaxWsHandler(String value) {
		employeeNumber = value;
	}

	public boolean handleFault(SOAPMessageContext context) {
		this.log.warn(new FedExLogEntry(context.toString()));
		System.out.println("Soap Fault:" + context.toString());
		return true;
	}

	public boolean handleMessage(SOAPMessageContext context) {
		String myToken = "";
		boolean outboundRequest = ((Boolean)context.get("javax.xml.ws.handler.message.outbound")).booleanValue();
		if (outboundRequest) {
			myToken = getToken();
			setSecurityHeader(context, myToken);
		}
		return true;
	}

	private void setSecurityHeader(SOAPMessageContext context, String userValue) {
		Boolean outboundProperty = (Boolean)context.get("javax.xml.ws.handler.message.outbound");
		if (outboundProperty.booleanValue()) {
			try {
				SOAPEnvelope envelope = context.getMessage().getSOAPPart().getEnvelope();
				SOAPHeader header = envelope.getHeader();
				if (header == null) {
					header = envelope.addHeader();
				}
				SOAPElement security = header.addChildElement("Security", "wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
				SOAPElement usernameToken = security.addChildElement("UsernameToken", "wsse");
				SOAPElement username = usernameToken.addChildElement("Username", "wsse");
				username.addTextNode(userValue);
			}
			catch (Exception e) {
				System.out.println("Failed to add user token profile security" + e);
			}
		}
	}

	private String getToken() {
		return gen.getToken("943415_cds");
	}

	public Set<QName> getHeaders() {
		return null;
	}

	public void close(MessageContext context) {
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\cds\client\security\SecurityJaxWsHandler.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */