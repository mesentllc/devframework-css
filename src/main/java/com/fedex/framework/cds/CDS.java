package com.fedex.framework.cds;

import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;
import javax.jws.soap.SOAPBinding;
import javax.xml.bind.annotation.XmlSeeAlso;

@WebService(name = "CDS", targetNamespace = "http://www.fedex.com/xmlns/cds2/ws")
@SOAPBinding(parameterStyle = SOAPBinding.ParameterStyle.BARE)
@XmlSeeAlso({ObjectFactory.class})
public interface CDS {
	@WebMethod
	@WebResult(name = "addResponse", targetNamespace = "http://www.fedex.com/xmlns/cds2", partName = "addResponse")
	AddResponse add(@WebParam(name = "addRequest", targetNamespace = "http://www.fedex.com/xmlns/cds2", partName = "addRequest") AddRequest paramAddRequest);

	@WebMethod
	@WebResult(name = "chainedQueryResponse", targetNamespace = "http://www.fedex.com/xmlns/cds2", partName = "chainedQueryResponse")
	ChainedQueryResponse chainedQuery(@WebParam(name = "chainedQueryRequest", targetNamespace = "http://www.fedex.com/xmlns/cds2", partName = "chainedQueryRequest") ChainedQueryRequest paramChainedQueryRequest);

	@WebMethod
	@WebResult(name = "compositeResponse", targetNamespace = "http://www.fedex.com/xmlns/cds2", partName = "compositeResponse")
	CompositeResponse composite(@WebParam(name = "compositeRequest", targetNamespace = "http://www.fedex.com/xmlns/cds2", partName = "compositeRequest") CompositeRequest paramCompositeRequest);

	@WebMethod
	@WebResult(name = "deleteResponse", targetNamespace = "http://www.fedex.com/xmlns/cds2", partName = "deleteResponse")
	DeleteResponse delete(@WebParam(name = "deleteRequest", targetNamespace = "http://www.fedex.com/xmlns/cds2", partName = "deleteRequest") DeleteRequest paramDeleteRequest);

	@WebMethod
	@WebResult(name = "enrichedQueryResponse", targetNamespace = "http://www.fedex.com/xmlns/cds2", partName = "enrichedQueryResponse")
	EnrichedQueryResponse enrichedQuery(@WebParam(name = "enrichedQueryRequest", targetNamespace = "http://www.fedex.com/xmlns/cds2", partName = "enrichedQueryRequest") EnrichedQueryRequest paramEnrichedQueryRequest);

	@WebMethod
	@WebResult(name = "enrichedUpdateResponse", targetNamespace = "http://www.fedex.com/xmlns/cds2", partName = "enrichedUpdateResponse")
	EnrichedUpdateResponse enrichedUpdate(@WebParam(name = "enrichedUpdateRequest", targetNamespace = "http://www.fedex.com/xmlns/cds2", partName = "enrichedUpdateRequest") EnrichedUpdateRequest paramEnrichedUpdateRequest);

	@WebMethod
	@WebResult(name = "indexQueryResponse", targetNamespace = "http://www.fedex.com/xmlns/cds2", partName = "indexQueryResponse")
	IndexQueryResponse indexQuery(@WebParam(name = "indexQueryRequest", targetNamespace = "http://www.fedex.com/xmlns/cds2", partName = "indexQueryRequest") IndexQueryRequest paramIndexQueryRequest);

	@WebMethod
	@WebResult(name = "insertResponse", targetNamespace = "http://www.fedex.com/xmlns/cds2", partName = "insertResponse")
	InsertResponse insert(@WebParam(name = "insertRequest", targetNamespace = "http://www.fedex.com/xmlns/cds2", partName = "insertRequest") InsertRequest paramInsertRequest);

	@WebMethod
	@WebResult(name = "importDataResponse", targetNamespace = "http://www.fedex.com/xmlns/cds2", partName = "importDataResponse")
	ImportDataResponse importData(@WebParam(name = "importDataRequest", targetNamespace = "http://www.fedex.com/xmlns/cds2", partName = "importDataRequest") ImportDataRequest paramImportDataRequest);

	@WebMethod
	void transfer();

	@WebMethod
	@WebResult(name = "keyQueryResponse", targetNamespace = "http://www.fedex.com/xmlns/cds2", partName = "keyQueryResponse")
	KeyQueryResponse keyQuery(@WebParam(name = "keyQueryRequest", targetNamespace = "http://www.fedex.com/xmlns/cds2", partName = "keyQueryRequest") KeyQueryRequest paramKeyQueryRequest);

	@WebMethod
	@WebResult(name = "modifyResponse", targetNamespace = "http://www.fedex.com/xmlns/cds2", partName = "modifyResponse")
	ModifyResponse modify(@WebParam(name = "modifyRequest", targetNamespace = "http://www.fedex.com/xmlns/cds2", partName = "modifyRequest") ModifyRequest paramModifyRequest);

	@WebMethod
	@WebResult(name = "restoreResponse", targetNamespace = "http://www.fedex.com/xmlns/cds2", partName = "restoreResponse")
	RestoreResponse restore(@WebParam(name = "restoreRequest", targetNamespace = "http://www.fedex.com/xmlns/cds2", partName = "restoreRequest") RestoreRequest paramRestoreRequest);

	@WebMethod
	@WebResult(name = "sequenceResponse", targetNamespace = "http://www.fedex.com/xmlns/cds2", partName = "sequenceResponse")
	SequenceResponse sequenceGenerator(@WebParam(name = "sequenceRequest", targetNamespace = "http://www.fedex.com/xmlns/cds2", partName = "sequenceRequest") SequenceRequest paramSequenceRequest);
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\framework\cds\CDS.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */