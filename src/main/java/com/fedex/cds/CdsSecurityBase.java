package com.fedex.cds;

import com.fedex.enterprise.security.cds.authZ.AuditRecord;
import com.fedex.enterprise.security.utils.LDAPSearch;
import com.fedex.framework.cds.InsertRequest;
import com.fedex.framework.cds.KeyQueryRequest;
import com.fedex.framework.cds.StanzaIdType;
import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import com.fedex.security.common.StringUtils;
import org.w3c.dom.Document;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.ws.soap.SOAPFaultException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

public class CdsSecurityBase {
	public enum STANZAS {
		action,
		applicationRole,
		customAuthZClass,
		extendedRule,
		extRuleXRef,
		groupAudit,
		groupRole,
		resource,
		restriction,
		role,
		rule,
		userRole;

		STANZAS() {
		}
	}

	private static final FedExLoggerInterface logger = FedExLogger.getLogger(CdsSecurityBase.class);
	protected static final com.fedex.framework.cds.ObjectFactory cdsObjectFactory = new com.fedex.framework.cds.ObjectFactory();
	public static final String ESC_APP_ID = "4112";
	public static final String ESC_APP_ID_FOR_AUTH = "APP4112";
	protected static final String DOMAIN = "authZ";
	public static final String ACTION_STANZA = "action";

	protected enum RoleInfoStanzas {
		groupRole,
		userRole,
		applicationRole,
		restriction,
		defaultRole;

		RoleInfoStanzas() {
		}
	}

	public static final String EXTENDED_RULE_STANZA = "extendedRule";
	public static final String XREF_STANZA = "extRuleXRef";
	public static final String RESOURCE_STANZA = "resource";
	public static final String RULE_STANZA = "rule";
	public static final String GROUP_ROLE_STANZA = "groupRole";
	public static final String USER_ROLE_STANZA = "userRole";
	public static final String ROLE_STANZA = "role";
	public static final String RESTRICTION_STANZA = "restriction";
	public static final String ROLE_OWNER_STANZA = "roleOwner";
	public static final String GROUP_OWNER_STANZA = "groupOwner";
	public static final String APPLICATION_ROLE_STANZA = "applicationRole";
	public static final String AUDIT_RECORD_STANZA = "auditRecord";
	public static final String CUSTOM_AUTHZCLASS_STANZA = "customAuthZClass";
	public static final String GROUP_AUDIT_STANZA = "groupAudit";
	protected static final Long EMPTY_VALUE = Long.valueOf(5120135L);
	protected static final int MAX_KEYS_FOR_CDS_REQUEST = 500;
	protected static final int MAX_RESULTS_FOR_CDS_REQUEST = 45;
	public static int STANZA_DESC_MAJOR_VER = 1;
	public static int STANZA_DESC_MINOR_VER = 0;
	public static final String ESC_ACTION_CREATE = "create";
	public static final String ESC_ACTION_MODIFY = "modify";
	public static final String ESC_ACTION_VIEW = "view";
	public static final String ESC_ACTION_MANAGE = "manage";
	public static final String ESC_ACTION_DELETE = "delete";
	public static final String ACTION_ESC_RESOURCE = "/ACTION/";
	public static final String ACTION_APP_XPATH = "/action/@ApplicationId";
	public static final String ACTION_NAME_XPATH = "/action/@ActionName";
	public static final String ACTION_DESC_XPATH = "/action/@ActionDesc";
	public static final String RESOURCE_ESC_RESOURCE = "/RESOURCE/";
	public static final String RESOURCE_APP_XPATH = "/resource/@ApplicationId";
	public static final String RESOURCE_NAME_XPATH = "/resource/@ResourceName";
	public static final String RESOURCE_DESC_XPATH = "/resource/@ResourceDesc";
	public static final String RESOURCE_ROOTFLG_XPATH = "/resource/@RootFlg";
	public static final String ROLE_ESC_RESOURCE = "/ROLE/";
	public static final String ROLE_ROLEID_XPATH = "/role/@RoleDocId";
	public static final String ROLE_ROLENAME_XPATH = "/role/@RoleName";
	public static final String ROLE_APP_XPATH = "/role/@RoleScopeName";
	public static final String ROLE_DESC_XPATH = "/role/@RoleDesc";
	public static final String ROLE_TYPE_XPATH = "/role/@RoleScopeType";
	public static final String ROLE_SCOPE_TYPE_APP = "Application";
	public static final String ROLE_SCOPE_TYPE_REALM = "Realm";
	public static final String ROLEOWNER_ESC_RESOURCE = "/ROLE/";
	public static final String ROLEOWNER_ROLEID_XPATH = "/roleOwner/@RoleDocId";
	public static final String ROLEOWNER_FEDEXID_XPATH = "/roleOwner/@RoleOwnerFedExId";
	public static final String USERROLE_ESC_RESOURCE = "/ROLE/";
	public static final String USERROLE_ROLEID_XPATH = "/userRole/@RoleDocId";
	public static final String USERROLE_NAME_XPATH = "/userRole/@UserFedExId";
	public static final String APPROLE_ESC_RESOURCE = "/ROLE/";
	public static final String APPROLE_ROLEID_XPATH = "/applicationRole/@RoleDocId";
	public static final String APPROLE_NAME_XPATH = "/applicationRole/@ApplicationId";
	public static final String GROUPROLE_ESC_RESOURCE = "/ROLE/";
	public static final String GROUPROLE_ROLEID_XPATH = "/groupRole/@RoleDocId";
	public static final String GROUPROLE_NAME_XPATH = "/groupRole/@GroupName";
	public static final String RULE_ESC_RESOURCE = "/POLICY/";
	public static final String RULE_APP_XPATH = "/rule/@ApplicationId";
	public static final String RULE_ACTIONID_XPATH = "/rule/@ActionDocId";
	public static final String RULE_RESOURCEID_XPATH = "/rule/@ResourceDocId";
	public static final String RULE_ROLEID_XPATH = "/rule/@RoleDocId";
	public static final String RULE_GRANTDENY_XPATH = "/rule/@GrantDenyFlg";
	public static final String RULE_CUSTOM_XPATH = "/rule/@CustAuthZDocId";
	public static final String EXTRULE_ESC_RESOURCE = "/POLICY/EXTRULE/";
	public static final String EXTRULE_APP_XPATH = "/extendedRule/@ApplicationId";
	public static final String EXTRULE_KEY_XPATH = "/extendedRule/@ExtendedRuleKey";
	public static final String EXTRULE_OPERATOR_XPATH = "/extendedRule/@ExtendedRuleOperator";
	public static final String EXTRULE_VALUETYPE_XPATH = "/extendedRule/@ExtendedRuleValueType";
	public static final String EXTRULE_VALUE_XPATH = "/extendedRule/@ExtendedRuleValue";
	public static final String EXTRULEXREF_ESC_RESOURCE = "/POLICY/EXTRULE/";
	public static final String EXTRULEXREF_APP_XPATH = "/extRuleXRef/@ApplicationId";
	public static final String EXTRULEXREF_RULEID_XPATH = "/extRuleXRef/@RuleDocId";
	public static final String EXTRULEXREF_EXTRULEID_XPATH = "/extRuleXRef/@ExtRuleDocId";
	public static final String GROUPOWNER_ESC_RESOURCE = "/GROUP/";
	public static final String GROUPOWNER_GROUPNAME_XPATH = "/groupOwner/@GroupName";
	public static final String GROUPOWNER_ROLEID_XPATH = "/groupOwner/@RoleDocId";
	public static final String AUDITRECORD_ESC_RESOURCE = "/AUDITRECORD/";
	public static final String AUDITRECORD_APP_XPATH = "/auditRecord/@AppOrRealm";
	public static final String AUDITRECORD_TMSTP_XPATH = "/auditRecord/@EventTmstp";
	public static final String AUDITRECORD_IMPACTED_STANZA_XPATH = "/auditRecord/@ImpactedStanza";
	public static final String AUDITRECORD_EVENT_TYPE_XPATH = "/auditRecord/@EventType";
	public static final String CUSTAUTHZCLASS_ESC_RESOURCE = "/POLICY/";
	public static final String CUSTAUTHZCLASS_APP_XPATH = "/customAuthZClass/@ApplicationId";
	public static final String CUSTAUTHZCLASS_NAME_XPATH = "/customAuthZClass/@CustomAuthZClassName";
	public static final String CUSTAUTHZCLASS_DESC_XPATH = "/customAuthZClass/@CustomAuthZClassDesc";
	public static final String GROUPAUDIT_GROUP_NAME_XPATH = "/groupAudit/@GroupName";
	public static final String GROUPAUDIT_DATE_CHANGED_XPATH = "/groupAudit/@DateChanged";
	public static final String RESTRICTION_APP_XPATH = "/restriction/APPID";
	public static final String RESTRICTION_USER_XPATH = "/restriction/USERID";
	public static final String RESTRICTION_ROLE_XPATH = "/restriction/ROLENAME";
	public static final String RESTRICTION_RESTRICTION_DATA_ITEM_XPATH = "/restriction/restrictionItem";
	public static final String RESTRICTION_XPATH = "/restriction";
	public static final String RESTRICTION_SEQUENCE = "restrictionSequence";
	protected static CdsClient cdsClient = null;
	protected static LDAPSearch ldapSearch = null;
	protected static JAXBContext cdsAuthZContext = null;
	protected static Unmarshaller cdsAuthZUnmarshaller = null;

	static {
		try {
			cdsAuthZContext = JAXBContext.newInstance("com.fedex.enterprise.security.cds.authZ");
			cdsAuthZUnmarshaller = cdsAuthZContext.createUnmarshaller();
		}
		catch (JAXBException e) {
			logger.error(new FedExLogEntry("Error initializing CDS AuthZ Unmarshaller : " + e.getMessage()), e);
			throw new RuntimeException("Error initializing CDS AuthZ Unmarshaller : " + e.getMessage(), e);
		}
	}

	public CdsClient getCdsClient() {
		return cdsClient;
	}

	public void setCdsClient(CdsClient cdsClient) {
		cdsClient = cdsClient;
	}

	public LDAPSearch getLdapSearch() {
		return ldapSearch;
	}

	public void setLdapSearch(LDAPSearch ldapSearch) {
		ldapSearch = ldapSearch;
	}

	public int getStanzaDescMajorVer() {
		return STANZA_DESC_MAJOR_VER;
	}

	public void setStanzaDescMajorVer(int stanzaDescMajorVer) {
		STANZA_DESC_MAJOR_VER = stanzaDescMajorVer;
	}

	public int getStanzaDescMinorVer() {
		return STANZA_DESC_MINOR_VER;
	}

	public void setStanzaDescMinorVer(int stanzaDescMinorVer) {
		STANZA_DESC_MINOR_VER = stanzaDescMinorVer;
	}

	protected static Document BuildDocument() {
		DocumentBuilder db = null;
		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			db = dbf.newDocumentBuilder();
		}
		catch (ParserConfigurationException pce) {
			logger.error(new FedExLogEntry("Error in the BuildDocument"), pce);
			throw new RuntimeException(pce.getMessage(), pce);
		}
		return db.newDocument();
	}

	public static void Delete(List<Long> keys, String stanza, List<InsertRequest.InsertItem> auditRecords) {
		Delete(keys, stanza, auditRecords, false);
	}

	public static void Delete(List<Long> keys, String stanza, List<InsertRequest.InsertItem> auditRecords, boolean systemOverride) {
		try {
			cdsClient.delete(keys, "authZ", stanza, auditRecords, systemOverride);
		}
		catch (SOAPFaultException sfe) {
			throw new RuntimeException(sfe.getMessage(), sfe);
		}
	}

	public static void Delete(Long key, String stanza, InsertRequest.InsertItem auditRecord) {
		Delete(key, stanza, auditRecord, false);
	}

	public static void Delete(Long key, String stanza, InsertRequest.InsertItem auditRecord, boolean systemOverride) {
		try {
			ArrayList<Long> list = new ArrayList();
			list.add(key);
			ArrayList<InsertRequest.InsertItem> list2 = null;
			if (auditRecord != null) {
				list2 = new ArrayList();
				list2.add(auditRecord);
			}
			Delete(list, stanza, list2, systemOverride);
		}
		catch (SOAPFaultException sfe) {
			throw new RuntimeException(sfe.getMessage(), sfe);
		}
	}

	protected static KeyQueryRequest buildKeyQueryRequest(List<Long> keyList) {
		return buildKeyQueryRequest(keyList, "");
	}

	protected static KeyQueryRequest buildKeyQueryRequest(List<Long> keyList, String stanzaName) {
		com.fedex.framework.cds.ObjectFactory of = new com.fedex.framework.cds.ObjectFactory();
		KeyQueryRequest.StanzaId stanzaId = of.createKeyQueryRequestStanzaId();
		stanzaId.setDomain("authZ");
		if (!StringUtils.isNullOrBlank(stanzaName)) {
			stanzaId.setName(stanzaName);
		}
		KeyQueryRequest keyQueryRequest = of.createKeyQueryRequest();
		keyQueryRequest.getStanzaId().add(stanzaId);
		for (Long key : keyList) {
			keyQueryRequest.getKey().add(key.toString());
		}
		return keyQueryRequest;
	}

	public InsertRequest.InsertItem createAuditRecord(String appid, String onBehalfOf, String desc, String eventType, String stanza) {
		AuditRecord record = null;
		InsertRequest.InsertItem insertItem = new InsertRequest.InsertItem();
		try {
			com.fedex.enterprise.security.cds.authZ.ObjectFactory securityObjectFactory = new com.fedex.enterprise.security.cds.authZ.ObjectFactory();
			record = securityObjectFactory.createAuditRecord();
			record.setAppOrRealm(appid);
			record.setChangedBy(onBehalfOf);
			if (desc.length() > 4096) {
				desc = desc.substring(0, 4095);
			}
			record.setEventDesc(desc);
			record.setEventTmstp(getDateTime());
			record.setEventType(eventType);
			record.setImpactedStanza(stanza);
			record.setDomain("authZ");
			record.setMajorVersion(STANZA_DESC_MAJOR_VER);
			record.setMinorVersion(STANZA_DESC_MINOR_VER);
			logger.warn(new FedExLogEntry("Audit: " + desc));
			JAXBContext jaxbContext = JAXBContext.newInstance("com.fedex.enterprise.security.cds.authZ");
			Marshaller marshaller = jaxbContext.createMarshaller();
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document document = db.newDocument();
			marshaller.marshal(record, document);
			insertItem.getAny().add(document.getDocumentElement());
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Unable to write this information to the audit record: " + record));
			logger.warn(new FedExLogEntry("Due to this error: " + e));
		}
		return insertItem;
	}

	public static InsertRequest.InsertItem createStaticAuditRecord(String appid, String onBehalfOf, String desc, String eventType, String stanza) {
		AuditRecord record = null;
		InsertRequest.InsertItem insertItem = new InsertRequest.InsertItem();
		try {
			com.fedex.enterprise.security.cds.authZ.ObjectFactory securityObjectFactory = new com.fedex.enterprise.security.cds.authZ.ObjectFactory();
			record = securityObjectFactory.createAuditRecord();
			record.setAppOrRealm(appid);
			record.setChangedBy(onBehalfOf);
			if (desc.length() > 4096) {
				desc = desc.substring(0, 4095);
			}
			record.setEventDesc(desc);
			record.setEventTmstp(getStaticDateTime());
			record.setEventType(eventType);
			record.setImpactedStanza(stanza);
			record.setDomain("authZ");
			record.setMajorVersion(STANZA_DESC_MAJOR_VER);
			record.setMinorVersion(STANZA_DESC_MINOR_VER);
			logger.warn(new FedExLogEntry("Audit: " + desc));
			JAXBContext jaxbContext = JAXBContext.newInstance("com.fedex.enterprise.security.cds.authZ");
			Marshaller marshaller = jaxbContext.createMarshaller();
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document document = db.newDocument();
			marshaller.marshal(record, document);
			insertItem.getAny().add(document.getDocumentElement());
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Unable to write this information to the audit record: " + record));
			logger.warn(new FedExLogEntry("Due to this error: " + e));
		}
		return insertItem;
	}

	public static AuditRecord createStaticAuditRecordObject(String appid, String onBehalfOf, String desc, String eventType, String stanza) {
		AuditRecord record = null;
		try {
			com.fedex.enterprise.security.cds.authZ.ObjectFactory securityObjectFactory = new com.fedex.enterprise.security.cds.authZ.ObjectFactory();
			record = securityObjectFactory.createAuditRecord();
			record.setAppOrRealm(appid);
			record.setChangedBy(onBehalfOf);
			if (desc.length() > 4096) {
				desc = desc.substring(0, 4095);
			}
			record.setEventDesc(desc);
			record.setEventTmstp(getStaticDateTime());
			record.setEventType(eventType);
			record.setImpactedStanza(stanza);
			record.setDomain("authZ");
			record.setMajorVersion(STANZA_DESC_MAJOR_VER);
			record.setMinorVersion(STANZA_DESC_MINOR_VER);
			logger.warn(new FedExLogEntry("Audit: " + desc));
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Unable to write this information to the audit record: " + record));
			logger.warn(new FedExLogEntry("Due to this error: " + e));
		}
		return record;
	}

	public XMLGregorianCalendar getDateTime() {
		DatatypeFactory dataFactory = null;
		XMLGregorianCalendar cal = null;
		try {
			dataFactory = DatatypeFactory.newInstance();
			cal = dataFactory.newXMLGregorianCalendar();
			Calendar c = Calendar.getInstance();
			cal.setYear(c.get(1));
			cal.setMonth(c.get(2) + 1);
			cal.setDay(c.get(5));
			cal.setHour(c.get(11));
			cal.setMinute(c.get(12));
			cal.setSecond(c.get(13));
			cal.setMillisecond(c.get(14));
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Unable to get the datatype factory to create dates for the : " + e));
		}
		return cal;
	}

	public static XMLGregorianCalendar getStaticDateTime() {
		DatatypeFactory dataFactory = null;
		XMLGregorianCalendar cal = null;
		try {
			dataFactory = DatatypeFactory.newInstance();
			cal = dataFactory.newXMLGregorianCalendar();
			Calendar c = Calendar.getInstance();
			cal.setYear(c.get(1));
			cal.setMonth(c.get(2) + 1);
			cal.setDay(c.get(5));
			cal.setHour(c.get(11));
			cal.setMinute(c.get(12));
			cal.setSecond(c.get(13));
			cal.setMillisecond(c.get(14));
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Unable to get the datatype factory to create dates for the : " + e));
		}
		return cal;
	}

	public String formatAppId(String appId) {
		if ((appId != null) && (!appId.trim().isEmpty())) {
			String formatAppId = appId.trim();
			if (formatAppId.length() >= 4) {
				return appId;
			}
			if (formatAppId.length() == 3) {
				return formatAppId;
			}
			if (formatAppId.length() == 2) {
				return formatAppId;
			}
			return formatAppId;
		}
		return appId;
	}

	public static String formatStaticAppId(String appId) {
		if ((appId != null) && (!appId.trim().isEmpty())) {
			String formatAppId = appId.trim();
			if (formatAppId.length() >= 4) {
				return appId;
			}
			if (formatAppId.length() == 3) {
				return "0" + appId;
			}
			if (formatAppId.length() == 2) {
				return "00" + appId;
			}
			return "000" + appId;
		}
		return appId;
	}

	protected static StanzaIdType getQueryItemStanzaId(String domain, String name) {
		StanzaIdType restrictionRoleStanzaId = null;
		if ((domain != null) && (!domain.isEmpty()) && (name != null) && (!name.isEmpty())) {
			restrictionRoleStanzaId = cdsObjectFactory.createStanzaIdType();
			restrictionRoleStanzaId.setDomain(domain);
			restrictionRoleStanzaId.setName(name);
		}
		else {
			logger.warn(new FedExLogEntry("Provided Domain or Name to get QueryItemStanzaId NULL/EMPTY, Domain = " + domain + ", Name = " + name));
		}
		return restrictionRoleStanzaId;
	}

	protected static StanzaIdType getQueryItemIndexStanzaId(String domain, String name) {
		StanzaIdType queryItemIndexStanzaId = null;
		if ((domain != null) && (!domain.isEmpty()) && (name != null) && (!name.isEmpty())) {
			queryItemIndexStanzaId = cdsObjectFactory.createStanzaIdType();
			queryItemIndexStanzaId.setDomain(domain);
			queryItemIndexStanzaId.setName(name);
		}
		else {
			logger.warn(new FedExLogEntry("Provided Domain or Name to get QueryItemIndexStanzaId NULL/EMPTY, Domain = " + domain + ", Name = " + name));
		}
		return queryItemIndexStanzaId;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\cds\CdsSecurityBase.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */