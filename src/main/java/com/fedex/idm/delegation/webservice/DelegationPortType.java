package com.fedex.idm.delegation.webservice;

import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.ws.RequestWrapper;
import javax.xml.ws.ResponseWrapper;
import java.util.List;

@WebService(name = "DelegationPortType", targetNamespace = "http://delegationv2.idm.fedex.com/")
@XmlSeeAlso({ObjectFactory.class})
public interface DelegationPortType {
	@WebMethod
	@WebResult(targetNamespace = "")
	@RequestWrapper(localName = "getDelegates", targetNamespace = "http://delegationv2.idm.fedex.com/", className = "com.fedex.idm.delegation.webservice.GetDelegates")
	@ResponseWrapper(localName = "getDelegatesResponse", targetNamespace = "http://delegationv2.idm.fedex.com/", className = "com.fedex.idm.delegation.webservice.GetDelegatesResponse")
	List<Object> getDelegates(@WebParam(name = "arg0", targetNamespace = "") String paramString1, @WebParam(name = "arg1", targetNamespace = "") String paramString2);

	@WebMethod
	@WebResult(targetNamespace = "")
	@RequestWrapper(localName = "getDelegators", targetNamespace = "http://delegationv2.idm.fedex.com/", className = "com.fedex.idm.delegation.webservice.GetDelegators")
	@ResponseWrapper(localName = "getDelegatorsResponse", targetNamespace = "http://delegationv2.idm.fedex.com/", className = "com.fedex.idm.delegation.webservice.GetDelegatorsResponse")
	List<Object> getDelegators(@WebParam(name = "arg0", targetNamespace = "") String paramString1, @WebParam(name = "arg1", targetNamespace = "") String paramString2);

	@WebMethod
	@WebResult(targetNamespace = "")
	@RequestWrapper(localName = "getAssignments", targetNamespace = "http://delegationv2.idm.fedex.com/", className = "com.fedex.idm.delegation.webservice.GetAssignments")
	@ResponseWrapper(localName = "getAssignmentsResponse", targetNamespace = "http://delegationv2.idm.fedex.com/", className = "com.fedex.idm.delegation.webservice.GetAssignmentsResponse")
	List<Object> getAssignments(@WebParam(name = "appId", targetNamespace = "") String paramString1, @WebParam(name = "delegatee", targetNamespace = "") String paramString2, @WebParam(name = "delegator", targetNamespace = "") String paramString3, @WebParam(name = "function", targetNamespace = "") String paramString4);

	@WebMethod
	@WebResult(targetNamespace = "")
	@RequestWrapper(localName = "getAssignmentsForAppID", targetNamespace = "http://delegationv2.idm.fedex.com/", className = "com.fedex.idm.delegation.webservice.GetAssignmentsForAppID")
	@ResponseWrapper(localName = "getAssignmentsForAppIDResponse", targetNamespace = "http://delegationv2.idm.fedex.com/", className = "com.fedex.idm.delegation.webservice.GetAssignmentsForAppIDResponse")
	List<AssignmentReturnVO> getAssignmentsForAppID(@WebParam(name = "appId", targetNamespace = "") String paramString1, @WebParam(name = "function", targetNamespace = "") String paramString2);
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\idm\delegation\webservice\DelegationPortType.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */