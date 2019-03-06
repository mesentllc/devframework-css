package com.fedex.cds;

import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import org.springframework.ws.soap.SoapFaultDetail;
import org.springframework.ws.soap.SoapFaultDetailElement;
import org.springframework.ws.soap.client.SoapFaultClientException;

import javax.xml.transform.dom.DOMResult;
import java.util.Iterator;

public class SoapFaultMessage {
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(SoapFaultMessage.class);

	public static void ThrowRuntimeException(SoapFaultClientException sfce) {
		SoapFaultDetail soapFaultDetail = sfce.getSoapFault().getFaultDetail();
		Iterator<SoapFaultDetailElement> it = soapFaultDetail.getDetailEntries();
		SoapFaultDetailElement detailElementChild = it.next();
		logger.warn(new FedExLogEntry("[SoapFault]: " + ((DOMResult)detailElementChild.getResult()).getNode().getTextContent()));
		throw new RuntimeException(((DOMResult)detailElementChild.getResult()).getNode().getTextContent());
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\cds\SoapFaultMessage.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */