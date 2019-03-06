package com.fedex.cds;

import com.fedex.common.icefaces.util.FacesUtils;
import com.fedex.enterprise.security.cds.authZ.GroupOwner;
import com.fedex.enterprise.security.cds.authZ.GroupRole;
import com.fedex.enterprise.security.esc.view.model.DataBean;
import com.fedex.enterprise.security.esc.view.model.WssoHandler;
import com.fedex.enterprise.security.role.GroupRoleData;
import com.fedex.enterprise.security.utils.EscUtils;
import com.fedex.framework.cds.IndexElementType;
import com.fedex.framework.cds.IndexQueryResponse;
import com.fedex.framework.cds.InsertRequest;
import com.fedex.framework.cds.KeyQueryRequest;
import com.fedex.framework.cds.KeyQueryResponse;
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

public class CdsSecurityGroupOwner
		extends CdsSecurityBase {
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(CdsSecurityGroupOwner.class);

	public static long Insert(GroupRoleData newGrpData) {
		return Insert(newGrpData, false);
	}

	public static long Insert(GroupRoleData newGrpData, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		if (!systemOverride) {
			WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
			onBehalfOf = roleHandler.getUserId();
		}
		return Insert(newGrpData, systemOverride, onBehalfOf, "");
	}

	public static long Insert(GroupRoleData newGrpData, boolean systemOverride, String onBehalfOf, String appId) {
		List<Long> keys = null;
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
			GroupOwner cdsGroupRole = securityObjectFactory.createGroupOwner();
			cdsGroupRole.setDomain("authZ");
			cdsGroupRole.setGroupName(newGrpData.getGroupNm());
			cdsGroupRole.setRoleDocId(newGrpData.getRoleDocId());
			cdsGroupRole.setMajorVersion(STANZA_DESC_MAJOR_VER);
			cdsGroupRole.setMinorVersion(STANZA_DESC_MINOR_VER);
			Document doc = BuildDocument();
			propMarshaller.marshal(cdsGroupRole, doc);
			request.add(doc);
			DataBean dataBean = (DataBean)FacesUtils.getManagedBean("dataBean");
			String roleName = dataBean.getRoleName(cdsGroupRole.getRoleDocId());
			String desc = roleName + " was assigned as managing role for the group " + cdsGroupRole.getGroupName() + " by " + onBehalfOf + " from " + (callingApp.equals("4112") ? "the ESC." : new StringBuilder().append("App #").append(callingApp).toString());
			InsertRequest.InsertItem auditRecord = createStaticAuditRecord("4112", onBehalfOf, desc, "create", "groupOwner");
			List<InsertRequest.InsertItem> auditRecords = new ArrayList();
			auditRecords.add(auditRecord);
			keys = cdsClient.insert(request, auditRecords, systemOverride);
		}
		catch (SoapFaultClientException sfx) {
			throw sfx;
		}
		catch (JAXBException jbEx) {
			logger.warn(new FedExLogEntry("Caught JAXB Exception ex: " + jbEx.toString()));
			throw new RuntimeException(jbEx.getMessage(), jbEx);
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Caught general Exception ex: " + e.toString()));
			throw new RuntimeException(e.getMessage(), e);
		}
		return keys.get(0).longValue();
	}

	public static void Delete(GroupRoleData grpOwner) {
		Delete(grpOwner, false);
	}

	public static void Delete(GroupRoleData grpOwner, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		if (!systemOverride) {
			WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
			onBehalfOf = roleHandler.getUserId();
		}
		Delete(grpOwner, false, onBehalfOf, "");
	}

	public static void Delete(GroupRoleData grpOwner, boolean systemOverride, String onBehalfOf, String appId) {
		try {
			String callingApp = "";
			if (EscUtils.isNullOrBlank(appId)) {
				callingApp = "4112";
			}
			else {
				callingApp = appId;
			}
			DataBean dataBean = (DataBean)FacesUtils.getManagedBean("dataBean");
			String roleName = dataBean.getRoleName(grpOwner.getRoleDocId());
			String desc = roleName + " was removed as the managing role for group " + grpOwner.getGroupNm() + " by " + onBehalfOf + " from " + (callingApp.equals("4112") ? "the ESC." : new StringBuilder().append("App #").append(callingApp).toString());
			InsertRequest.InsertItem auditRecord = createStaticAuditRecord(callingApp, onBehalfOf, desc, "delete", "extendedRule");
			Delete(Long.valueOf(grpOwner.getDocId()), "groupOwner", auditRecord, systemOverride);
		}
		catch (SoapFaultClientException sfx) {
			throw sfx;
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Caught general Exception ex: " + e.toString()));
			throw new RuntimeException(e);
		}
	}

	public static List<GroupRoleData> Retrieve(String grpName, Bookmark bookmarkId) {
		if (bookmarkId == null) {
			bookmarkId = new Bookmark();
			bookmarkId.setBookmark("5120135");
		}
		String bookmark = "";
		List<GroupRoleData> response = new ArrayList();
		int totalDocCount = 0;
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		StanzaIdType stanzaId = of.createStanzaIdType();
		stanzaId.setDomain("authZ");
		stanzaId.setName("groupOwner");
		StanzaIdType indexStanzaId = of.createStanzaIdType();
		indexStanzaId.setDomain("authZ");
		indexStanzaId.setName("groupOwner");
		Unmarshaller unmarshaller;
		do {
			IndexQueryResponse indexResponse = cdsClient.indexQuery(BuildIndexQuery(grpName), stanzaId, indexStanzaId, bookmark);
			List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
			JAXBContext groupRoleStanzaContext = null;
			unmarshaller = null;
			try {
				groupRoleStanzaContext = JAXBContext.newInstance(GroupOwner.class);
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityGroupOwner Retrieve new instance"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			try {
				unmarshaller = groupRoleStanzaContext.createUnmarshaller();
			}
			catch (JAXBException e1) {
				logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityGroupOwner Retrieve create unmarshaller"), e1);
				throw new RuntimeException(e1.getMessage(), e1);
			}
			for (IndexQueryResponse.QueryItem queryItem : queryItemList) {
				for (Iterator i$ = queryItem.getKeyedStanzas().iterator(); i$.hasNext(); ) {
					KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
					totalDocCount++;
					List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
					for (KeyedStanzasType.Stanza s : stanzaList) {
						Element docElement = s.getAny();
						GroupOwner currentGroupRole = null;
						try {
							currentGroupRole = (GroupOwner)unmarshaller.unmarshal(docElement);
							GroupRoleData newGroupRoleData = new GroupRoleData();
							newGroupRoleData.setGroupNm(currentGroupRole.getGroupName());
							newGroupRoleData.setRoleDocId(currentGroupRole.getRoleDocId());
							newGroupRoleData.setDocId(keyedStanzas.getKey());
							response.add(newGroupRoleData);
						}
						catch (JAXBException e) {
							logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityGroupOwner Retrieve unmarshal"), e);
						}
						continue;
					}
				}
				bookmark = queryItem.getPaging().getBookmark();
			}
		}
		while (!"".equals(bookmark));
		bookmarkId.setBookmark(bookmark);
		logger.info(new FedExLogEntry("TOTAL DOC COUNT FOR GroupOwner = " + totalDocCount));
		return response;
	}

	public static GroupRoleData RetrieveByKey(long docId) {
		Unmarshaller unmarshaller = null;
		JAXBContext extRefStanzaContext = null;
		GroupRoleData groupRoleData = null;
		try {
			extRefStanzaContext = JAXBContext.newInstance(GroupRoleData.class);
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityGroupOwner RetrieveByKey new instance"), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		try {
			unmarshaller = extRefStanzaContext.createUnmarshaller();
		}
		catch (JAXBException e1) {
			logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityGroupOwner RetrieveByKey create unmarshaller"), e1);
			throw new RuntimeException(e1.getMessage(), e1);
		}
		try {
			List<Long> keys = new ArrayList();
			keys.add(Long.valueOf(docId));
			KeyQueryRequest request = buildKeyQueryRequest(keys, "groupOwner");
			KeyQueryResponse response = cdsClient.keyQuery(request);
			for (Iterator i$ = response.getKeyedStanzas().iterator(); i$.hasNext(); ) {
				KeyedStanzasType keyedStanzas = (KeyedStanzasType)i$.next();
				List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
				for (KeyedStanzasType.Stanza s : stanzaList) {
					Element docElement = s.getAny();
					GroupRole currentGroupRole = null;
					try {
						currentGroupRole = (GroupRole)unmarshaller.unmarshal(docElement);
						groupRoleData = new GroupRoleData();
						groupRoleData.setGroupNm(currentGroupRole.getGroupName());
						groupRoleData.setRoleDocId(currentGroupRole.getRoleDocId());
						groupRoleData.setDocId(keyedStanzas.getKey());
					}
					catch (JAXBException e) {
						logger.error(new FedExLogEntry("Caught JAXBException in CdsSecurityGroupOwner RetrieveByKey unmarshall"), e);
					}
					continue;
				}
			}
		}
		catch (SoapFaultClientException sfx) {
			throw sfx;
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Caught general Exception ex: " + e.toString()));
			throw new RuntimeException(e);
		}
		return groupRoleData;
	}

	private static List<IndexElementType> BuildIndexQuery(String groupName) {
		List<IndexElementType> indexElements = new ArrayList();
		IndexElementType grpNameValue = new IndexElementType();
		grpNameValue.setXpath("/groupOwner/@GroupName");
		grpNameValue.setComparison("equals");
		grpNameValue.setValue(groupName);
		indexElements.add(grpNameValue);
		return indexElements;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\cds\CdsSecurityGroupOwner.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */