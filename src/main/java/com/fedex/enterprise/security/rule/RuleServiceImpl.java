package com.fedex.enterprise.security.rule;

import com.fedex.cds.Bookmark;
import com.fedex.cds.CdsSecurityBase;
import com.fedex.cds.CdsSecurityCustomAuthorizer;
import com.fedex.cds.CdsSecurityExtRuleXRef;
import com.fedex.cds.CdsSecurityExtendedRule;
import com.fedex.cds.CdsSecurityRule;
import com.fedex.common.icefaces.util.FacesUtils;
import com.fedex.enterprise.security.customauthz.CustomAuthzData;
import com.fedex.enterprise.security.esc.view.model.WssoHandler;
import com.fedex.enterprise.security.jms.EventType;
import com.fedex.enterprise.security.jms.JmsAuditRecordUser;
import com.fedex.enterprise.security.jms.SecurityPublisherImpl;
import com.fedex.enterprise.security.utils.EscUtils;
import com.fedex.framework.cds.InsertRequest;
import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import com.fedex.security.server.AuthorizorFactory;

import java.util.ArrayList;
import java.util.List;

public class RuleServiceImpl
		implements RuleService {
	private static final FedExLoggerInterface LOGGER = FedExLogger.getLogger(RuleServiceImpl.class);
	private static final String JMS_ACTION = "receive";
	private static final String JMS_LOA_RESOURCE = "jms/LossOfAccessMessage/";
	private SecurityPublisherImpl securityPublisher;

	public void setSecurityPublisher(SecurityPublisherImpl securityPublisher) {
		this.securityPublisher = securityPublisher;
	}

	public SecurityPublisherImpl getSecurityPublisher() {
		return this.securityPublisher;
	}

	public void deleteExtRuleByKey(long docId) {
		LOGGER.info(new FedExLogEntry("RuleServiceImpl.deleteExtRuleByKey"));
		CdsSecurityExtendedRule.Delete(docId);
	}

	public void deleteRuleByKey(long docId, boolean systemOverride, String onBehalfOf, String appId) {
		LOGGER.info(new FedExLogEntry("RuleServiceImpl.deleteRuleByKey"));
		RuleData ruleData = EscUtils.getRuleNameByDocId(docId);
		JmsAuditRecordUser jmsRecord = null;
		if ((ruleData.getAppId() != null) && (AuthorizorFactory.getAuthorizor().isAllowed(EscUtils.prependAPP(ruleData.getAppId()), "jms/LossOfAccessMessage/", "receive"))) {
			List<String> members = EscUtils.getRoleMembers(ruleData.getRoleDocId());
			jmsRecord = new JmsAuditRecordUser();
			jmsRecord.setEventType(EventType.RULE_DELETED);
			jmsRecord.setRoleName(ruleData.getRoleNm());
			jmsRecord.setApplicationID(Long.parseLong(ruleData.getAppId()));
			jmsRecord.setEventTmstp(CdsSecurityBase.getStaticDateTime());
			jmsRecord.setEventDesc(" Rule was deleted ");
			if (members.size() > 10000) {
				jmsRecord.setErrorDesc(" There were more than 10,000 members in the role who lost access because of the rule deletion ");
			}
			else {
				for (String uid : members) {
					jmsRecord.getImpactedEmployeeID().add(uid);
				}
			}
		}
		if ((onBehalfOf == null) && (appId == null)) {
			CdsSecurityRule.Delete(docId);
		}
		else {
			CdsSecurityRule.Delete(docId, systemOverride, onBehalfOf, appId);
		}
		if (jmsRecord != null) {
			this.securityPublisher.publishMessage(jmsRecord);
		}
	}

	public void deleteRuleByKey(long docId) {
		deleteRuleByKey(docId, false, null, null);
	}

	public List<RuleData> getAccessListForId(String id, String idType) {
		LOGGER.info(new FedExLogEntry("RuleServiceImpl.getAccessListForId-[NOT IMPLEMENTED]"));
		throw new RuntimeException("Not Implemented.");
	}

	public List<ExtendedRuleData> getExtendedRulesForApplication(String appId, Bookmark bookmark) {
		LOGGER.info(new FedExLogEntry("RuleServiceImpl.getExtendedRulesForApplication"));
		return CdsSecurityExtendedRule.Retrieve(appId, bookmark);
	}

	public List<CustomAuthzData> getCustAuthzsForApplication(String appId, Bookmark bookmark) {
		LOGGER.info(new FedExLogEntry("RuleServiceImpl.getCustAuthzsForApplication"));
		return CdsSecurityCustomAuthorizer.getCustomAuthzsForApplication(appId);
	}

	public List<ExtendedRuleData> getExtendedRulesForRuleId(long ruleId, Bookmark bookmark) {
		LOGGER.info(new FedExLogEntry("RuleServiceImpl.getExtendedRulesForRuleId"));
		List<ExtendedRuleXrefData> list = CdsSecurityExtRuleXRef.Retrieve(ruleId, bookmark);
		if ((list != null) && (!list.isEmpty())) {
			List<Long> keys = new ArrayList();
			for (ExtendedRuleXrefData current : list) {
				keys.add(Long.valueOf(current.getExtRuleDocId()));
			}
			return CdsSecurityExtendedRule.Retrieve(keys);
		}
		return new ArrayList();
	}

	public List<ExtendedRuleXrefData> getExtendedRuleXrefForRuleId(long ruleId, Bookmark bookmark) {
		LOGGER.info(new FedExLogEntry("RuleServiceImpl.getExtendedRulesXrefForRuleId"));
		return CdsSecurityExtRuleXRef.Retrieve(ruleId, bookmark);
	}

	public List<RuleData> getRulesForApplication(String appId, Bookmark bookmark) {
		return CdsSecurityRule.Retrieve(appId, bookmark);
	}

	public List<RuleData> getRulesForResource(long resDocId, Bookmark bookmark) {
		return CdsSecurityRule.RetrieveByResourceDocId(resDocId, bookmark);
	}

	public List<RuleData> getRulesForRole(long roleDocId, Bookmark bookmark) {
		return CdsSecurityRule.RetrieveByRoleDocId(roleDocId, bookmark);
	}

	public long insertExtRule(ExtendedRuleData extRuleData) {
		LOGGER.info(new FedExLogEntry("RuleServiceImpl.insertExtRule"));
		return CdsSecurityExtendedRule.Insert(extRuleData);
	}

	public Long insertRule(RuleData ruleData) {
		LOGGER.info(new FedExLogEntry("RuleServiceImpl.insertExtRule"));
		return CdsSecurityRule.Insert(ruleData);
	}

	public void updateExtRule(ExtendedRuleData extRuleData) {
		LOGGER.info(new FedExLogEntry("RuleServiceImpl.updateExtRule"));
		CdsSecurityExtendedRule.Update(extRuleData);
	}

	public void updateCustomAuthzr(CustomAuthzData custuthzData) {
		LOGGER.info(new FedExLogEntry("RuleServiceImpl.updateCustomAuthzr"));
		CdsSecurityCustomAuthorizer.updateCustomAuthz(custuthzData, false);
	}

	public void updateRule(RuleData ruleData) {
		CdsSecurityRule.Update(ruleData);
	}

	public void addExtRule(ExtendedRuleXrefData xRef) {
		CdsSecurityExtRuleXRef.Insert(xRef);
	}

	public void removeExtRule(Long key) {
		removeExtRule(key, false);
	}

	public void removeExtRule(Long key, boolean systemOverride) {
		if ((key != null) && (key.longValue() != 0L)) {
			String onBehalfOf = "APP4112";
			String callingApp = "4112";
			if (!systemOverride) {
				WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
				onBehalfOf = roleHandler.getUserId();
			}
			ExtendedRuleXrefData extRuleXref = CdsSecurityExtRuleXRef.RetrieveOne(key.longValue());
			String desc = "Extended Rule #" + extRuleXref.getExtRuleDocId() + " was removed from Rule #" + extRuleXref.getRuleDocId() + " by " + onBehalfOf + " from " + ("4112".equals("4112") ? "the ESC." : "App #4112");
			InsertRequest.InsertItem auditRecord = CdsSecurityBase.createStaticAuditRecord(extRuleXref.getAppId(), onBehalfOf, desc, "delete", "extRuleXRef");
			CdsSecurityExtRuleXRef.Delete(key, "extRuleXRef", auditRecord);
		}
	}

	public long insertCustomAuthorizer(CustomAuthzData customAuthzData) {
		LOGGER.info(new FedExLogEntry("RuleServiceImpl.insertCustomAuthorizer"));
		return CdsSecurityCustomAuthorizer.insertCustomAuthz(customAuthzData, true);
	}

	public void deleteCustomAuthorizer(CustomAuthzData customAuthzData) {
		LOGGER.info(new FedExLogEntry("RuleServiceImpl.deleteCustomAuthorizer"));
		CdsSecurityCustomAuthorizer.deleteCustomAuthz(customAuthzData, false);
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\rule\RuleServiceImpl.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */