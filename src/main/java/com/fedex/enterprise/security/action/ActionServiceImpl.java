package com.fedex.enterprise.security.action;

import com.fedex.cds.Bookmark;
import com.fedex.cds.CdsSecurityAction;
import com.fedex.cds.CdsSecurityBase;
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

public class ActionServiceImpl
		implements ActionService {
	private static final FedExLoggerInterface LOGGER = FedExLogger.getLogger(ActionServiceImpl.class);
	public static final String JMS_LOA_RESOURCE = "jms/LossOfAccessMessage/";
	public static final String JMS_ACTION = "receive";
	private CdsSecurityAction cdsSecurityAction;
	private SecurityPublisherImpl securityPublisher;

	public void setSecurityPublisher(SecurityPublisherImpl securityPublisher) {
		this.securityPublisher = securityPublisher;
	}

	public SecurityPublisherImpl getSecurityPublisher() {
		return this.securityPublisher;
	}

	public CdsSecurityAction getCdsSecurityAction() {
		return this.cdsSecurityAction;
	}

	public void setCdsSecurityAction(CdsSecurityAction cdsSecurityAction) {
		this.cdsSecurityAction = cdsSecurityAction;
	}

	public List<ActionData> getActionsForApplication(String appId, Bookmark bookmarkId) {
		if (bookmarkId == null) {
			bookmarkId = new Bookmark();
		}
		return this.cdsSecurityAction.getActionsForApplication(appId, bookmarkId);
	}

	public List<ActionData> getActionsForApplicationByPartialActionName(String appId, String partActionNm, Bookmark bookmarkId) {
		return null;
	}

	public ActionData getAction(long docId) {
		return CdsSecurityAction.getActionByKey(Long.valueOf(docId));
	}

	public long insertAction(ActionData actionData) {
		return this.cdsSecurityAction.insertAction(actionData);
	}

	public void deleteAction(ActionData actionData) {
		deleteAction(actionData, false, null, null);
	}

	public void deleteAction(ActionData actionData, boolean systemOverride, String onBehalfOf, String appId) {
		List<JmsAuditRecordUser> jmsAuditRecordUserList = null;
		if ((actionData.getAppId() != null) && (AuthorizorFactory.getAuthorizor().isAllowed(EscUtils.prependAPP(actionData.getAppId()), "jms/LossOfAccessMessage/", "receive"))) {
			jmsAuditRecordUserList = new ArrayList();
			List<RuleData> rules = CdsSecurityRule.Retrieve(actionData.getAppId(), new Bookmark());
			if ((rules != null) && (!rules.isEmpty())) {
				for (RuleData rule : rules) {
					if (rule.getActionDocId() == actionData.getDocId()) {
						List<String> members = EscUtils.getRoleMembers(rule.getRoleDocId());
						JmsAuditRecordUser jmsRecord = new JmsAuditRecordUser();
						jmsRecord.setEventType(EventType.RULE_DELETED);
						jmsRecord.setRoleName(rule.getRoleNm());
						jmsRecord.setApplicationID(Long.parseLong(rule.getAppId()));
						jmsRecord.setEventTmstp(CdsSecurityBase.getStaticDateTime());
						jmsRecord.setEventDesc(" Rule was deleted because action '" + actionData.getActionNm() + "' was deleted ");
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
		}
		else {
			if (LOGGER.infoEnabled()) {
				LOGGER.info(new FedExLogEntry("Sending LossOfAccess JMS Message for the application " + actionData.getAppId() + " is not allowed"));
			}
		}
		if ((onBehalfOf == null) && (appId == null)) {
			this.cdsSecurityAction.deleteAction(actionData);
		}
		else {
			this.cdsSecurityAction.deleteAction(actionData, systemOverride, onBehalfOf, appId);
		}
		if (jmsAuditRecordUserList != null) {
			for (JmsAuditRecordUser jmsRecord : jmsAuditRecordUserList) {
				this.securityPublisher.publishMessage(jmsRecord);
			}
			if (LOGGER.infoEnabled()) {
				LOGGER.info(new FedExLogEntry("Sent " + jmsAuditRecordUserList.size() + " LossOfAccess JMS Messages for the application " + actionData.getAppId()));
			}
		}
	}

	public void updateAction(ActionData actionData) {
		this.cdsSecurityAction.updateAction(actionData);
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\action\ActionServiceImpl.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */