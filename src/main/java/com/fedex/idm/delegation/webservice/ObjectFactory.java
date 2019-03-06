package com.fedex.idm.delegation.webservice;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.annotation.XmlElementDecl;
import javax.xml.bind.annotation.XmlRegistry;
import javax.xml.namespace.QName;

@XmlRegistry
public class ObjectFactory {
	private static final QName _GetAssignments_QNAME = new QName("http://delegationv2.idm.fedex.com/", "getAssignments");
	private static final QName _GetAssignmentsResponse_QNAME = new QName("http://delegationv2.idm.fedex.com/", "getAssignmentsResponse");
	private static final QName _GetDelegators_QNAME = new QName("http://delegationv2.idm.fedex.com/", "getDelegators");
	private static final QName _GetDelegatorsResponse_QNAME = new QName("http://delegationv2.idm.fedex.com/", "getDelegatorsResponse");
	private static final QName _GetAssignmentsForAppID_QNAME = new QName("http://delegationv2.idm.fedex.com/", "getAssignmentsForAppID");
	private static final QName _GetDelegatesResponse_QNAME = new QName("http://delegationv2.idm.fedex.com/", "getDelegatesResponse");
	private static final QName _GetAssignmentsForAppIDResponse_QNAME = new QName("http://delegationv2.idm.fedex.com/", "getAssignmentsForAppIDResponse");
	private static final QName _GetDelegates_QNAME = new QName("http://delegationv2.idm.fedex.com/", "getDelegates");

	public GetDelegates createGetDelegates() {
		return new GetDelegates();
	}

	public GetDelegatesResponse createGetDelegatesResponse() {
		return new GetDelegatesResponse();
	}

	public GetDelegators createGetDelegators() {
		return new GetDelegators();
	}

	public AssignmentReturnVO createAssignmentReturnVO() {
		return new AssignmentReturnVO();
	}

	public GetAssignmentsForAppID createGetAssignmentsForAppID() {
		return new GetAssignmentsForAppID();
	}

	public GetAssignmentsResponse createGetAssignmentsResponse() {
		return new GetAssignmentsResponse();
	}

	public GetAssignmentsForAppIDResponse createGetAssignmentsForAppIDResponse() {
		return new GetAssignmentsForAppIDResponse();
	}

	public GetAssignments createGetAssignments() {
		return new GetAssignments();
	}

	public GetDelegatorsResponse createGetDelegatorsResponse() {
		return new GetDelegatorsResponse();
	}

	@XmlElementDecl(namespace = "http://delegationv2.idm.fedex.com/", name = "getAssignments")
	public JAXBElement<GetAssignments> createGetAssignments(GetAssignments value) {
		return new JAXBElement(_GetAssignments_QNAME, GetAssignments.class, null, value);
	}

	@XmlElementDecl(namespace = "http://delegationv2.idm.fedex.com/", name = "getAssignmentsResponse")
	public JAXBElement<GetAssignmentsResponse> createGetAssignmentsResponse(GetAssignmentsResponse value) {
		return new JAXBElement(_GetAssignmentsResponse_QNAME, GetAssignmentsResponse.class, null, value);
	}

	@XmlElementDecl(namespace = "http://delegationv2.idm.fedex.com/", name = "getDelegators")
	public JAXBElement<GetDelegators> createGetDelegators(GetDelegators value) {
		return new JAXBElement(_GetDelegators_QNAME, GetDelegators.class, null, value);
	}

	@XmlElementDecl(namespace = "http://delegationv2.idm.fedex.com/", name = "getDelegatorsResponse")
	public JAXBElement<GetDelegatorsResponse> createGetDelegatorsResponse(GetDelegatorsResponse value) {
		return new JAXBElement(_GetDelegatorsResponse_QNAME, GetDelegatorsResponse.class, null, value);
	}

	@XmlElementDecl(namespace = "http://delegationv2.idm.fedex.com/", name = "getAssignmentsForAppID")
	public JAXBElement<GetAssignmentsForAppID> createGetAssignmentsForAppID(GetAssignmentsForAppID value) {
		return new JAXBElement(_GetAssignmentsForAppID_QNAME, GetAssignmentsForAppID.class, null, value);
	}

	@XmlElementDecl(namespace = "http://delegationv2.idm.fedex.com/", name = "getDelegatesResponse")
	public JAXBElement<GetDelegatesResponse> createGetDelegatesResponse(GetDelegatesResponse value) {
		return new JAXBElement(_GetDelegatesResponse_QNAME, GetDelegatesResponse.class, null, value);
	}

	@XmlElementDecl(namespace = "http://delegationv2.idm.fedex.com/", name = "getAssignmentsForAppIDResponse")
	public JAXBElement<GetAssignmentsForAppIDResponse> createGetAssignmentsForAppIDResponse(GetAssignmentsForAppIDResponse value) {
		return new JAXBElement(_GetAssignmentsForAppIDResponse_QNAME, GetAssignmentsForAppIDResponse.class, null, value);
	}

	@XmlElementDecl(namespace = "http://delegationv2.idm.fedex.com/", name = "getDelegates")
	public JAXBElement<GetDelegates> createGetDelegates(GetDelegates value) {
		return new JAXBElement(_GetDelegates_QNAME, GetDelegates.class, null, value);
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\idm\delegation\webservice\ObjectFactory.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */