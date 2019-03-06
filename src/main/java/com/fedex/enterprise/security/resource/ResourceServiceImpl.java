package com.fedex.enterprise.security.resource;

import com.fedex.cds.Bookmark;
import com.fedex.cds.CdsSecurityBase;
import com.fedex.cds.CdsSecurityResource;
import com.fedex.cds.CdsSecurityRule;
import com.fedex.enterprise.security.jms.EventType;
import com.fedex.enterprise.security.jms.JmsAuditRecordUser;
import com.fedex.enterprise.security.jms.SecurityPublisherImpl;
import com.fedex.enterprise.security.rule.RuleData;
import com.fedex.enterprise.security.utils.EscUtils;
import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import com.fedex.security.server.AuthorizorFactory;

import java.util.ArrayList;
import java.util.List;

public class ResourceServiceImpl
		implements ResourceService {
	private static final FedExLoggerInterface LOGGER = FedExLogger.getLogger(ResourceServiceImpl.class);
	private static final String JMS_ACTION = "receive";
	private static final String JMS_LOA_RESOURCE = "jms/LossOfAccessMessage/";
	private CdsSecurityResource cdsSecurityResource;
	private SecurityPublisherImpl securityPublisher;

	public void setSecurityPublisher(SecurityPublisherImpl securityPublisher) {
		this.securityPublisher = securityPublisher;
	}

	public SecurityPublisherImpl getSecurityPublisher() {
		return this.securityPublisher;
	}

	public CdsSecurityResource getCdsSecurityResource() {
		return this.cdsSecurityResource;
	}

	public void setCdsSecurityResource(CdsSecurityResource cdsSecurityResource) {
		this.cdsSecurityResource = cdsSecurityResource;
	}

	public List<ResourceData> getResourcesForApplicationByRoot(String appId, String rootNm) {
		return this.cdsSecurityResource.getResourceRootsForApplication(appId, null);
	}

	public ResourceData getResource(long docId) {
		return CdsSecurityResource.getResourceByKey(Long.valueOf(docId));
	}

	public long insertResource(ResourceData resourceData) {
		return this.cdsSecurityResource.insertResource(resourceData);
	}

	public void updateResource(ResourceData resourceData) {
		this.cdsSecurityResource.updateResource(resourceData);
	}

	public void deleteResourceByRoot(String appId, String root) {
		this.cdsSecurityResource.deleteResourceByRoot(appId, root);
	}

	class ResourceDataTree {
		List<ResourceData> children = new ArrayList();
		ResourceData node;

		ResourceDataTree(String appId, long docId, String description, long typeDocId, char rootFlg) {
			this.node = new ResourceData();
			this.node.setAppId(appId);
			this.node.setDocId(docId);
			this.node.setResDesc(description);
			this.node.setResTypeDocId(typeDocId);
			this.node.setRootFlg(rootFlg);
		}

		public List<ResourceData> getChildren() {
			return this.children;
		}

		public void setChildren(List<ResourceData> children) {
			this.children = children;
		}

		public ResourceData getNode() {
			return this.node;
		}

		public void setNode(ResourceData node) {
			this.node = node;
		}
	}

	public void deleteResource(ResourceData resourceData) {
		deleteResource(resourceData, false, null, null);
	}

	public void deleteResource(ResourceData resourceData, boolean systemOverride, String onBehalfOf, String appId) {
		List<JmsAuditRecordUser> jmsAuditRecordUserList = null;
		if ((resourceData.getAppId() != null) && (AuthorizorFactory.getAuthorizor().isAllowed(EscUtils.prependAPP(resourceData.getAppId()), "jms/LossOfAccessMessage/", "receive"))) {
			jmsAuditRecordUserList = getDeleteJmsMessage(resourceData.getDocId(), resourceData.getResName());
		}
		else {
			if (LOGGER.infoEnabled()) {
				LOGGER.info(new FedExLogEntry("Sending LossOfAccess JMS Message for the application " + resourceData.getAppId() + " is not allowed"));
			}
		}
		if ((onBehalfOf == null) && (appId == null)) {
			this.cdsSecurityResource.deleteResource(resourceData);
		}
		else {
			this.cdsSecurityResource.deleteResource(resourceData, systemOverride, onBehalfOf, appId);
		}
		if (jmsAuditRecordUserList != null) {
			for (JmsAuditRecordUser jmsRecord : jmsAuditRecordUserList) {
				this.securityPublisher.publishMessage(jmsRecord);
			}
		}
	}

	private List<JmsAuditRecordUser> getDeleteJmsMessage(long resourceDocId, String resourceName) {
		List<JmsAuditRecordUser> jmsAuditRecordUserList = new ArrayList();
		try {
			List<RuleData> rules = CdsSecurityRule.RetrieveByResourceDocId(resourceDocId, new Bookmark());
			if ((rules != null) && (!rules.isEmpty())) {
				for (RuleData rule : rules) {
					List<String> members = EscUtils.getRoleMembers(rule.getRoleDocId());
					JmsAuditRecordUser jmsRecord = new JmsAuditRecordUser();
					jmsRecord.setEventType(EventType.RULE_DELETED);
					jmsRecord.setRoleName(rule.getRoleNm());
					jmsRecord.setApplicationID(Long.parseLong(rule.getAppId()));
					jmsRecord.setEventTmstp(CdsSecurityBase.getStaticDateTime());
					jmsRecord.setEventDesc(" Rule was deleted because resource '" + resourceName + "' was deleted ");
					if (members.size() > 10000) {
						jmsRecord.setErrorDesc(" There were more than 10,000 members in the role who lost access because of the rule deletion ");
					}
					else {
						for (String uid : members) {
							jmsRecord.getImpactedEmployeeID().add(uid);
						}
					}
					jmsAuditRecordUserList.add(jmsRecord);
				}
			}
		}
		catch (Exception e) {
			LOGGER.warn(new FedExLogEntry("WARNING: couldn't find the rules/extrulexrefs for this resource."));
		}
		return jmsAuditRecordUserList;
	}

	public List<ResourceData> getResourceRootsForApplication(String appId, Bookmark bookmark) {
		return this.cdsSecurityResource.getResourceRootsForApplication(appId, bookmark);
	}

	public List<ResourceData> getResourcesForApplication(String appId, Bookmark bookMark) {
		return this.cdsSecurityResource.getResourcesForApplication(appId, bookMark);
	}

	public List<ResourceData> getResourcesForApplicationByPartialResource(String appId, String partResName, Bookmark bookMark) {
		return this.cdsSecurityResource.getResourcesForApplicationByPartialResource(appId, partResName, bookMark);
	}

	public ResourceData getResourceByName(String appId, String resourceName) {
		return null;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\resource\ResourceServiceImpl.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */