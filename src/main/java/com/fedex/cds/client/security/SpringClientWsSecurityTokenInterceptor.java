package com.fedex.cds.client.security;

import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import com.fedex.security.client.PkcTokenGeneratorImpl;
import org.springframework.ws.client.WebServiceClientException;
import org.springframework.ws.client.core.WebServiceTemplate;
import org.springframework.ws.client.support.interceptor.ClientInterceptor;
import org.springframework.ws.context.MessageContext;
import org.springframework.ws.soap.SoapBody;
import org.springframework.ws.soap.SoapFaultDetail;
import org.springframework.ws.soap.SoapFaultDetailElement;
import org.springframework.ws.soap.saaj.SaajSoapMessage;

import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;
import javax.xml.transform.dom.DOMResult;
import java.util.Iterator;

public class SpringClientWsSecurityTokenInterceptor implements ClientInterceptor {
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(SpringClientWsSecurityTokenInterceptor.class);
	public static final String WSSE_NAMESPACE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
	public static final String WSU_NAMESPACE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
	private String defaultServiceAppId = null;
	private WebServiceTemplate webServiceTemplate;

	public WebServiceTemplate getWebServiceTemplate() {
		return this.webServiceTemplate;
	}

	public void setWebServiceTemplate(WebServiceTemplate webServiceTemplate) {
		this.webServiceTemplate = webServiceTemplate;
	}

	public boolean handleFault(MessageContext mc)
			throws WebServiceClientException {
		try {
			SaajSoapMessage saajSoapMessage = (SaajSoapMessage)mc.getResponse();
			SoapBody body = saajSoapMessage.getSoapBody();
			if (body.hasFault()) {
				SoapFaultDetail soapFaultDetail = body.getFault().getFaultDetail();
				Iterator<SoapFaultDetailElement> it = soapFaultDetail.getDetailEntries();
				String errorMessageDesc = "";
				while (it.hasNext()) {
					SoapFaultDetailElement detailElementChild = it.next();
					errorMessageDesc = ((DOMResult)detailElementChild.getResult()).getNode().getTextContent();
					logger.warn(new FedExLogEntry("Soap Fault: " + errorMessageDesc));
				}
			}
		}
		catch (Exception e1) {
			logger.warn(new FedExLogEntry("Crap, can't read the SOAP FAULT!"));
			e1.printStackTrace();
		}
		logger.warn(new FedExLogEntry("Finished with fault processing..."));
		return false;
	}

	public boolean handleRequest(MessageContext mc)
			throws WebServiceClientException {
		SaajSoapMessage saajSoapMessage = (SaajSoapMessage)mc.getRequest();
		addSecurityHeader(saajSoapMessage, getToken());
		return true;
	}

	public boolean handleResponse(MessageContext mc)
			throws WebServiceClientException {
		return true;
	}

	public String getDefaultServiceAppId() {
		return this.defaultServiceAppId;
	}

	public void setDefaultServiceAppId(String eaiAppId) {
		if ((eaiAppId != null) && (!"".equals(eaiAppId.trim()))) {
			this.defaultServiceAppId = eaiAppId;
		}
	}

	private void addSecurityHeader(SaajSoapMessage ssm, String tokenValue) {
		try {
			SOAPHeader header = ssm.getSaajMessage().getSOAPHeader();
			SOAPElement security = header.addChildElement("Security", "wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
			SOAPElement usernameToken = security.addChildElement("UsernameToken", "wsse");
			usernameToken.addAttribute(new javax.xml.namespace.QName("http://www.w3.org/2000/xmlns/", "wsu", "xmlns"), "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
			SOAPElement username = usernameToken.addChildElement("Username", "wsse");
			username.addTextNode(tokenValue);
		}
		catch (SOAPException e) {
			throw new RuntimeException("Failed to add user token profile security" + e);
		}
	}

	private String getToken() {
		String icAppId = ClientInvocationContext.getEndpointServiceAppId();
		String serviceId;
		if ((icAppId == null) || ("".equals(icAppId))) {
			if ((this.defaultServiceAppId == null) || ("".equals(this.defaultServiceAppId))) {
				throw new IllegalStateException("Clients must provide ClientInvocationContext.setEndpointServiceAppId('serviceAppId') value for the service invocation OR a default must be Spring injected via SpringClientWsSecurityInterceptor.setDefaultServiceAppId()");
			}
			serviceId = this.defaultServiceAppId;
		}
		else {
			serviceId = icAppId;
		}
		PkcTokenGeneratorImpl gen = PkcTokenGeneratorImpl.getInstance();
		String icEmployeeId = ClientInvocationContext.getUserId();
		String token;
		if ((icEmployeeId != null) && (!"".equals(icEmployeeId))) {
			token = gen.getToken(serviceId, icEmployeeId);
		}
		else {
			token = gen.getToken(serviceId);
		}
		ClientInvocationContext.clear();
		return token;
	}

	public void afterCompletion(MessageContext arg0, Exception arg1)
			throws WebServiceClientException {
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\cds\client\security\SpringClientWsSecurityTokenInterceptor.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */