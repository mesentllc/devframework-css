package com.fedex.cds;

import com.fedex.common.icefaces.util.FacesUtils;
import com.fedex.enterprise.security.cds.authZ.RoleOwner;
import com.fedex.enterprise.security.esc.view.model.DataBean;
import com.fedex.enterprise.security.esc.view.model.WssoHandler;
import com.fedex.enterprise.security.role.RoleOwnerData;
import com.fedex.enterprise.security.utils.EscUtils;
import com.fedex.framework.cds.IndexElementType;
import com.fedex.framework.cds.IndexQueryResponse;
import com.fedex.framework.cds.InsertRequest;
import com.fedex.framework.cds.KeyedStanzasType;
import com.fedex.framework.cds.StanzaIdType;
import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import org.springframework.ws.soap.client.SoapFaultClientException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class CdsSecurityRoleOwner
		extends CdsSecurityBase {
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(CdsSecurityRoleOwner.class);

	public static void Insert(RoleOwnerData newObjectList, long roleDocId) {
		Insert(newObjectList, roleDocId, false);
	}

	public static void Insert(RoleOwnerData newObject, long roleDocId, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		if (!systemOverride) {
			WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
			onBehalfOf = roleHandler.getUserId();
		}
		Insert(newObject, roleDocId, systemOverride, onBehalfOf, "");
	}

	public static void Insert(RoleOwnerData newObject, long roleDocId, boolean systemOverride, String onBehalfOf, String appId) {
		List<Document> request = new ArrayList();
		String callingApp = "";
		if (EscUtils.isNullOrBlank(appId)) {
			callingApp = "4112";
		}
		else {
			callingApp = appId;
		}
		try {
			com.fedex.enterprise.security.cds.authZ.ObjectFactory securityObjectFactory = new com.fedex.enterprise.security.cds.authZ.ObjectFactory();
			JAXBContext propJaxbContext = JAXBContext.newInstance("com.fedex.enterprise.security.cds.authZ");
			Marshaller propMarshaller = propJaxbContext.createMarshaller();
			RoleOwner cdsRoleOwner = securityObjectFactory.createRoleOwner();
			cdsRoleOwner.setRoleOwnerFedExId(Integer.toString(newObject.getEmpNbr()));
			if (roleDocId != 0L) {
				cdsRoleOwner.setRoleDocId(roleDocId);
			}
			else {
				cdsRoleOwner.setRoleDocId(newObject.getRoleDocId());
			}
			cdsRoleOwner.setDomain("authZ");
			cdsRoleOwner.setMajorVersion(STANZA_DESC_MAJOR_VER);
			cdsRoleOwner.setMinorVersion(STANZA_DESC_MINOR_VER);
			Document doc = BuildDocument();
			propMarshaller.marshal(cdsRoleOwner, doc);
			request.add(doc);
			DataBean dataBean = (DataBean)FacesUtils.getManagedBean("dataBean");
			String roleName = dataBean.getRoleName(cdsRoleOwner.getRoleDocId());
			String desc = cdsRoleOwner.getRoleOwnerFedExId() + " was assigned as owner of role " + roleName + " by " + onBehalfOf + " from " + (callingApp.equals("4112") ? "the ESC." : new StringBuilder().append("App #").append(callingApp).toString());
			InsertRequest.InsertItem auditRecord = createStaticAuditRecord(callingApp, onBehalfOf, desc, "create", "roleOwner");
			List<InsertRequest.InsertItem> auditRecords = new ArrayList();
			auditRecords.add(auditRecord);
			cdsClient.insert(request, auditRecords, systemOverride);
		}
		catch (SoapFaultClientException sfx) {
			throw sfx;
		}
		catch (JAXBException jbEx) {
			logger.warn(new FedExLogEntry("Caught JAXB Exception ex: " + jbEx.toString()));
			throw new RuntimeException(jbEx.toString(), jbEx);
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Caught general Exception ex: " + e.toString()));
			throw new RuntimeException(e.getMessage(), e);
		}
	}

	public static List<RoleOwnerData> Retrieve(long roleKey) {
		String bookmark = "";
		List<RoleOwnerData> response = new ArrayList();
		int totalDocCount = 0;
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		StanzaIdType stanzaId = of.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("roleOwner");
		StanzaIdType indexStanzaId = of.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("roleOwner");
		IndexQueryResponse indexResponse = null;
		Unmarshaller unmarshaller;
		do {
			try {
				indexResponse = cdsClient.indexQuery(BuildIndexQuery(roleKey), stanzaId, indexStanzaId, bookmark);
			}
			catch (SoapFaultClientException sfx) {
				throw sfx;
			}
			List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
			JAXBContext resourceStanzaContext = null;
			unmarshaller = null;
			try {
				resourceStanzaContext = JAXBContext.newInstance(RoleOwner.class);
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRole Retrieve new instance RoleOwner"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			try {
				unmarshaller = resourceStanzaContext.createUnmarshaller();
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRole Retrieve create unmarshaller "), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
				for (Iterator i$ = queryItem.getKeyedStanzas().iterator(); i$.hasNext(); ) {
					KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
					totalDocCount++;
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						RoleOwner currentRoleOwner = null;
						try {
							currentRoleOwner = (RoleOwner)unmarshaller.unmarshal(docElement);
							RoleOwnerData newRoleOwnerData = new RoleOwnerData();
							newRoleOwnerData.setDocId(keyedStanzas.getKey());
							newRoleOwnerData.setEmpNbr(Integer.parseInt(currentRoleOwner.getRoleOwnerFedExId()));
							newRoleOwnerData.setRoleDocId(currentRoleOwner.getRoleDocId());
							response.add(newRoleOwnerData);
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityRole Retrieve unmarshal"), e);
						}
						continue;
					}
				}
				bookmark = queryItem.getPaging().getBookmark();
			}
		}
		while (!"".equals(bookmark));
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR ROLE OWNER = " + totalDocCount));
		return response;
	}

	private static List<IndexElementType> BuildIndexQuery(long roleDocID) {
		List<IndexElementType> indexElements = new ArrayList();
		IndexElementType appId = new IndexElementType();
		appId.setXpath("/roleOwner/@RoleDocId");
		appId.setComparison("equals");
		appId.setValue(Long.toString(roleDocID));
		indexElements.add(appId);
		return indexElements;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\cds\CdsSecurityRoleOwner.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */