package com.fedex.cds.client.security;

import javax.xml.ws.handler.Handler;
import javax.xml.ws.handler.HandlerResolver;
import javax.xml.ws.handler.PortInfo;
import java.util.ArrayList;
import java.util.List;

public class MyHandlerResolver
		implements HandlerResolver {
	private List<Handler> handlerList = null;
	private String _employeeNumber;

	public MyHandlerResolver(String employeeNumber) {
		this.handlerList = null;
		this._employeeNumber = employeeNumber;
	}

	public List<Handler> getHandlerChain(PortInfo portInfo) {
		if (this.handlerList == null) {
			this.handlerList = new ArrayList();
			this.handlerList.add(new SecurityJaxWsHandler(this._employeeNumber));
		}
		return this.handlerList;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\cds\client\security\MyHandlerResolver.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */