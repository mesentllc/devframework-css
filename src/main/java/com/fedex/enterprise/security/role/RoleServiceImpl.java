package com.fedex.enterprise.security.role;

import com.fedex.cds.Bookmark;
import com.fedex.cds.CdsSecurityAppRole;
import com.fedex.cds.CdsSecurityBase;
import com.fedex.cds.CdsSecurityExtRuleXRef;
import com.fedex.cds.CdsSecurityGroupRole;
import com.fedex.cds.CdsSecurityResource;
import com.fedex.cds.CdsSecurityRestriction;
import com.fedex.cds.CdsSecurityRole;
import com.fedex.cds.CdsSecurityRule;
import com.fedex.cds.CdsSecurityUserRole;
import com.fedex.common.icefaces.util.FacesUtils;
import com.fedex.enterprise.security.esc.view.model.WssoHandler;
import com.fedex.enterprise.security.jms.EventType;
import com.fedex.enterprise.security.jms.JmsAuditRecordUser;
import com.fedex.enterprise.security.jms.RestrictionEntry;
import com.fedex.enterprise.security.jms.RestrictionItem;
import com.fedex.enterprise.security.jms.SecurityPublisherImpl;
import com.fedex.enterprise.security.resource.ResourceData;
import com.fedex.enterprise.security.role.restriction.Entry;
import com.fedex.enterprise.security.role.restriction.RestrictionData;
import com.fedex.enterprise.security.role.restriction.RestrictionDataItem;
import com.fedex.enterprise.security.role.restriction.RestrictionSequence;
import com.fedex.enterprise.security.rule.ExtendedRuleXrefData;
import com.fedex.enterprise.security.rule.RuleData;
import com.fedex.enterprise.security.utils.EscUtils;
import com.fedex.enterprise.security.utils.GrsUtils;
import com.fedex.framework.cds.CompositeResponse;
import com.fedex.framework.cds.InsertRequest;
import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import com.fedex.security.server.AuthorizorFactory;

import javax.faces.context.FacesContext;
import javax.xml.ws.soap.SOAPFaultException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class RoleServiceImpl
		implements RoleService {
	private static final String THE_ESC = "the ESC.";
	private static final String FROM = " from ";
	private static final String APP = "App #";
	private static final String WAS_REMOVED_FROM_THE = " was removed from the ";
	private static final String EXCEEDS_MAX_LIMIT_OF_10_000_MEMBERS = " exceeds max limit of 10,000 members";
	private static final String WAS_ADDED_TO = " was added to ";
	private static final String JMS_ACTION = "receive";
	private static final String JMS_GOA_RESOURCE = "jms/GainOfAccessMessage/";
	private static final String JMS_LOA_RESOURCE = "jms/LossOfAccessMessage/";
	private static final FedExLoggerInterface LOGGER = FedExLogger.getLogger(RoleServiceImpl.class);
	private SecurityPublisherImpl securityPublisher;
	private SecurityPublisherImpl gainOfAccessPublisher;

	public SecurityPublisherImpl getGainOfAccessPublisher() {
		return this.gainOfAccessPublisher;
	}

	public void setGainOfAccessPublisher(SecurityPublisherImpl gainOfAccessPublisher) {
		this.gainOfAccessPublisher = gainOfAccessPublisher;
	}

	public void setSecurityPublisher(SecurityPublisherImpl securityPublisher) {
		this.securityPublisher = securityPublisher;
	}

	public SecurityPublisherImpl getSecurityPublisher() {
		return this.securityPublisher;
	}

	public void deleteRoleForApplicationByKey(long docId) {
		deleteRoleForApplicationByKey(docId, false);
	}

	public void deleteRoleForApplicationByKey(long docId, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		try {
			if (!systemOverride) {
				WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
				onBehalfOf = roleHandler.getUserId();
			}
		}
		catch (SOAPFaultException sfe) {
			throw new RuntimeException(sfe.getMessage(), sfe);
		}
		deleteRoleForApplicationByKey(docId, systemOverride, onBehalfOf);
	}

	public void deleteRoleForApplicationByKey(long docId, boolean systemOverride, String onBehalfOf) {
		RoleData role = CdsSecurityRole.Retrieve(docId, true);
		if ((role.getAppMemberList() != null) && (role.getAppMemberList().size() > 0)) {
			for (AppRoleData appRole : role.getAppMemberList()) {
				deleteRoleApplicationForApplicationByKey(appRole.getRoleDocId(), systemOverride, onBehalfOf);
			}
		}
		if ((role.getGroupMemberList() != null) && (role.getGroupMemberList().size() > 0)) {
			for (GroupRoleData groupRole : role.getGroupMemberList()) {
				deleteRoleGroupForApplicationByKey(groupRole.getDocId(), systemOverride, onBehalfOf);
			}
		}
		if ((role.getUserMemberList() != null) && (role.getUserMemberList().size() > 0)) {
			for (UserRoleData userRole : role.getUserMemberList()) {
				deleteRoleUserForApplicationByKey(userRole.getDocId(), systemOverride, onBehalfOf);
			}
		}
		List<InsertRequest.InsertItem> auditRecordsForRules = new ArrayList();
		List<InsertRequest.InsertItem> auditRecords = new ArrayList();
		List<Long> ruleKeys = new ArrayList();
		List<Long> extRuleXrefKeys = new ArrayList();
		List<RuleData> rules = CdsSecurityRule.RetrieveByRoleDocId(role.getDocId(), new Bookmark());
		try {
			if ((rules != null) && (!rules.isEmpty())) {
				for (Iterator i$ = rules.iterator(); i$.hasNext(); ) {
					RuleData rule = (RuleData)i$.next();
					ruleKeys.add(Long.valueOf(rule.getDocId()));
					String desc = "Rule ' " + EscUtils.getRuleNameByDocId(rule.getDocId(), rule.getAppId()) + "' was removed by the ESC due to the deletion of role " + role.getRoleNm() + ".";
					InsertRequest.InsertItem auditItem = CdsSecurityBase.createStaticAuditRecord(role.getRoleScopeNm(), onBehalfOf, desc, "delete", "rule");
					auditRecordsForRules.add(auditItem);
					List<ExtendedRuleXrefData> extRuleXRef = CdsSecurityExtRuleXRef.Retrieve(rule.getDocId(), new Bookmark());
					for (ExtendedRuleXrefData xref : extRuleXRef) {
						String desc2 = "Extended Rule #" + xref.getDocId() + " was removed from Rule # " + rule.getDocId() + " by the ESC due to the deletion of role " + role.getRoleNm() + ".";
						InsertRequest.InsertItem item = CdsSecurityBase.createStaticAuditRecord(role.getRoleScopeNm(), onBehalfOf, desc2, "delete", "extRuleXRef");
						auditRecords.add(item);
						extRuleXrefKeys.add(Long.valueOf(xref.getDocId()));
					}
				}
			}
		}
		catch (Exception e) {
			LOGGER.warn(new FedExLogEntry("WARNING: couldn't find the rules/extrulexrefs for this resource."));
		}
		try {
			if ((extRuleXrefKeys != null) && (!extRuleXrefKeys.isEmpty())) {
				CdsSecurityExtRuleXRef.Delete(extRuleXrefKeys, "extRuleXRef", auditRecords);
			}
		}
		catch (Exception e) {
			LOGGER.warn(new FedExLogEntry("WARNING: unable to properly delete any XRefs for the rules."));
		}
		try {
			if ((ruleKeys != null) && (!ruleKeys.isEmpty())) {
				CdsSecurityRule.Delete(ruleKeys, "rule", auditRecordsForRules);
			}
		}
		catch (Exception e) {
			LOGGER.warn(new FedExLogEntry("WARNING: unable to properly delete rules for the resource in question."));
		}
		try {
			CdsSecurityResource cdsSecurityResource = new CdsSecurityResource();
			String roleName = role.getRoleNm() + "/";
			if (roleName.contains("*")) {
				roleName = "";
			}
			String resourceName = "4112/ROLE/" + roleName;
			ResourceData resource = cdsSecurityResource.getResourceByName("4112", resourceName);
			if (resource != null) {
				cdsSecurityResource.deleteResource(resource, systemOverride, onBehalfOf, "4112");
			}
		}
		catch (Exception e) {
			LOGGER.warn(new FedExLogEntry("WARNING: unable to properly delete rules for the resource protecting the role."));
		}
		String callingApp = "4112";
		String desc = role.getRoleNm() + " was deleted by " + onBehalfOf + " from " + ("4112".equals("4112") ? "the ESC." : "App #4112");
		InsertRequest.InsertItem auditRecord = CdsSecurityBase.createStaticAuditRecord(role.getRoleScopeNm(), onBehalfOf, desc, "delete", "role");
		CdsSecurityBase.Delete(Long.valueOf(docId), "role", auditRecord);
		try {
			List<RestrictionData> restrictionList = getRestrictionsForRole(role.getRoleScopeNm(), role.getRoleNm(), null);
			if (restrictionList != null) {
				for (RestrictionData res : restrictionList) {
					LOGGER.info(new FedExLogEntry("Removing rstriction from role:" + role));
					deleteRestriction(res, systemOverride, onBehalfOf, "4112");
				}
			}
		}
		catch (Exception e) {
			LOGGER.error(new FedExLogEntry("Caught General Exception in deleteRoleForApplicationByKey from RoleServiceImpl"), e);
		}
		if ((role.getRoleScopeNm() != null) && (AuthorizorFactory.getAuthorizor().isAllowed(EscUtils.prependAPP(role.getRoleScopeNm()), "jms/LossOfAccessMessage/", "receive"))) {
			JmsAuditRecordUser jmsRecord = new JmsAuditRecordUser();
			jmsRecord.setRoleName(role.getRoleNm());
			jmsRecord.setEventTmstp(CdsSecurityBase.getStaticDateTime());
			jmsRecord.setApplicationID(Long.parseLong(role.getRoleScopeNm()));
			jmsRecord.setEventType(EventType.ROLE_DELETED);
			jmsRecord.setEventDesc(desc);
			this.securityPublisher.publishMessage(jmsRecord);
		}
		else {
			if (LOGGER.infoEnabled()) {
				LOGGER.info(new FedExLogEntry("Sending LossOfAccess JMS Message for the application " + role.getRoleScopeNm() + " is not allowed"));
			}
		}
	}

	public void deleteRoleApplicationForApplicationByKey(long docId) {
		deleteRoleApplicationForApplicationByKey(docId, false);
	}

	public void deleteRoleApplicationForApplicationByKey(long docId, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		try {
			if (!systemOverride) {
				WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
				onBehalfOf = roleHandler.getUserId();
			}
		}
		catch (SOAPFaultException sfe) {
			throw new RuntimeException(sfe.getMessage(), sfe);
		}
		deleteRoleApplicationForApplicationByKey(docId, systemOverride, onBehalfOf);
	}

	public void deleteRoleApplicationForApplicationByKey(long docId, boolean systemOverride, String onBehalfOf) {
		AppRoleData appRoleData = CdsSecurityAppRole.RetrieveByKey(docId);
		if (appRoleData != null) {
			RoleData role = CdsSecurityRole.Retrieve(appRoleData.getRoleDocId(), false);
			String callingApp = "4112";
			String desc = appRoleData.getApplicationName() + " was removed from the " + role.getRoleNm() + " role by " + onBehalfOf + " from " + ("4112".equals("4112") ? "the ESC." : "App #4112");
			InsertRequest.InsertItem auditRecord = CdsSecurityBase.createStaticAuditRecord(role.getRoleScopeNm(), onBehalfOf, desc, "delete", "applicationRole");
			CdsSecurityBase.Delete(Long.valueOf(docId), "applicationRole", auditRecord);
		}
	}

	public void deleteRoleGroupForApplicationByKey(long docId) {
		deleteRoleGroupForApplicationByKey(docId, false);
	}

	public void deleteRoleGroupForApplicationByKey(long docId, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		try {
			if (!systemOverride) {
				WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
				onBehalfOf = roleHandler.getUserId();
			}
		}
		catch (SOAPFaultException sfe) {
			throw new RuntimeException(sfe.getMessage(), sfe);
		}
		deleteRoleGroupForApplicationByKey(docId, systemOverride, onBehalfOf);
	}

	public void deleteRoleGroupForApplicationByKey(long docId, boolean systemOverride, String onBehalfOf) {
		GrsUtils grsUtils = new GrsUtils();
		GroupRoleData groupRoleData = CdsSecurityGroupRole.RetrieveByKey(docId);
		if (groupRoleData != null) {
			RoleData role = CdsSecurityRole.Retrieve(groupRoleData.getRoleDocId(), false);
			String callingApp = "4112";
			String desc = groupRoleData.getGroupNm() + " was removed from the " + role.getRoleNm() + " role by " + onBehalfOf + " from " + ("4112".equals("4112") ? "the ESC." : "App #4112");
			InsertRequest.InsertItem auditRecord = CdsSecurityBase.createStaticAuditRecord(role.getRoleScopeNm(), onBehalfOf, desc, "delete", "groupRole");
			CdsSecurityBase.Delete(Long.valueOf(docId), "groupRole", auditRecord);
			if ((role.getRoleScopeNm() != null) && (AuthorizorFactory.getAuthorizor().isAllowed(EscUtils.prependAPP(role.getRoleScopeNm()), "jms/LossOfAccessMessage/", "receive"))) {
				JmsAuditRecordUser jmsRecord = new JmsAuditRecordUser();
				List<String> members = grsUtils.getMembersOfGroup(groupRoleData.getGroupNm());
				try {
					List<RestrictionData> restrictionList = getRestrictionsForUserOrGrp(role.getRoleScopeNm(), role.getRoleNm(), groupRoleData.getGroupNm());
					if (restrictionList != null) {
						for (RestrictionData res : restrictionList) {
							for (RestrictionDataItem restrictionDataItem : res.getRestrictionList()) {
								RestrictionItem restrictionItem = new RestrictionItem();
								jmsRecord.getRestrictionItem().add(restrictionItem);
								restrictionItem.setRestrictionDataItemIndex(restrictionDataItem.getRestrictionItemIndex());
								for (Entry entry : restrictionDataItem.getEntry()) {
									RestrictionEntry restrictionEntry = new RestrictionEntry();
									restrictionEntry.setKey(entry.getKey());
									restrictionEntry.setValue(entry.getValue());
									restrictionItem.getEntry().add(restrictionEntry);
								}
							}
							LOGGER.info(new FedExLogEntry("Removing restriction from role:" + groupRoleData));
							deleteRestriction(res, systemOverride, onBehalfOf, "4112");
						}
					}
				}
				catch (Exception e) {
					LOGGER.always("Unable to delete the restriction", e);
				}
				jmsRecord.setRoleName(role.getRoleNm());
				jmsRecord.setApplicationID(Long.parseLong(role.getRoleScopeNm()));
				jmsRecord.setEventTmstp(CdsSecurityBase.getStaticDateTime());
				jmsRecord.setGroupName(groupRoleData.getGroupNm());
				jmsRecord.setEventDesc(groupRoleData.getGroupNm() + " was removed from the " + role.getRoleNm());
				jmsRecord.setEventType(EventType.GROUP_REMOVED_FROM_ROLE);
				if (members.size() > 10000) {
					jmsRecord.setErrorDesc(groupRoleData.getGroupNm() + " exceeds max limit of 10,000 members");
				}
				else {
					for (String uid : members) {
						jmsRecord.getImpactedEmployeeID().add(uid);
					}
				}
				this.securityPublisher.publishMessage(jmsRecord);
			}
			else {
				if (LOGGER.infoEnabled()) {
					LOGGER.info(new FedExLogEntry("Sending LossOfAccess JMS Message for the application " + role.getRoleScopeNm() + " is not allowed"));
				}
			}
		}
		else {
			LOGGER.warn(new FedExLogEntry("Couldn't find the group role stanza!"));
		}
	}

	public void deleteRoleUserForApplicationByKey(long docId) {
		deleteRoleUserForApplicationByKey(docId, false);
	}

	public void deleteRoleUserForApplicationByKey(long docId, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		try {
			if (!systemOverride) {
				WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
				onBehalfOf = roleHandler.getUserId();
			}
		}
		catch (SOAPFaultException sfe) {
			throw new RuntimeException(sfe.getMessage(), sfe);
		}
		deleteRoleUserForApplicationByKey(docId, systemOverride, onBehalfOf);
	}

	public void deleteRoleUserForApplicationByKey(long docId, boolean systemOverride, String onBehalfOf) {
		UserRoleData userRoleData = CdsSecurityUserRole.RetrieveByKey(docId);
		if (userRoleData != null) {
			RoleData role = CdsSecurityRole.Retrieve(userRoleData.getRoleDocId(), false);
			String callingApp = "4112";
			String desc = userRoleData.getEmpNbr() + " was removed from the " + role.getRoleNm() + " role by " + onBehalfOf + " from " + ("4112".equals("4112") ? "the ESC." : "App #4112");
			InsertRequest.InsertItem auditRecord = CdsSecurityBase.createStaticAuditRecord(role.getRoleScopeNm(), onBehalfOf, desc, "delete", "userRole");
			CdsSecurityBase.Delete(Long.valueOf(docId), "userRole", auditRecord);
			if ((role.getRoleScopeNm() != null) && (AuthorizorFactory.getAuthorizor().isAllowed(EscUtils.prependAPP(role.getRoleScopeNm()), "jms/LossOfAccessMessage/", "receive"))) {
				JmsAuditRecordUser jmsRecord = new JmsAuditRecordUser();
				try {
					List<RestrictionData> restrictionList = getRestrictionsForUserOrGrp(role.getRoleScopeNm(), role.getRoleNm(), userRoleData.getEmpNbr());
					if ((restrictionList != null) && (!restrictionList.isEmpty())) {
						for (RestrictionData res : restrictionList) {
							for (RestrictionDataItem restrictionDataItem : res.getRestrictionList()) {
								RestrictionItem restrictionItem = new RestrictionItem();
								jmsRecord.getRestrictionItem().add(restrictionItem);
								restrictionItem.setRestrictionDataItemIndex(restrictionDataItem.getRestrictionItemIndex());
								for (Entry entry : restrictionDataItem.getEntry()) {
									RestrictionEntry restrictionEntry = new RestrictionEntry();
									restrictionEntry.setKey(entry.getKey());
									restrictionEntry.setValue(entry.getValue());
									restrictionItem.getEntry().add(restrictionEntry);
								}
							}
							LOGGER.info(new FedExLogEntry("Removing rstriction from role:" + userRoleData));
							deleteRestriction(res, systemOverride, onBehalfOf, String.valueOf(res.getAppId()));
						}
					}
					else {
						LOGGER.info("There is no restriction data for user " + userRoleData.getEmpNbr() + " in role " + role.getRoleNm());
					}
				}
				catch (Exception e) {
					LOGGER.always("Unable to delete the restriction", e);
				}
				jmsRecord.setRoleName(role.getRoleNm());
				jmsRecord.setEventTmstp(CdsSecurityBase.getStaticDateTime());
				jmsRecord.getImpactedEmployeeID().add(userRoleData.getEmpNbr());
				jmsRecord.setApplicationID(Long.parseLong(role.getRoleScopeNm()));
				jmsRecord.setEventType(EventType.USER_REMOVED_FROM_ROLE);
				jmsRecord.setEventDesc(userRoleData.getEmpNbr() + " was removed from the " + role.getRoleNm());
				this.securityPublisher.publishMessage(jmsRecord);
			}
			else {
				if (LOGGER.infoEnabled()) {
					LOGGER.info(new FedExLogEntry("Sending LossOfAccess JMS Message for the application " + role.getRoleScopeNm() + " is not allowed"));
				}
			}
		}
		else {
			LOGGER.warn(new FedExLogEntry("Couldn't find the user role entry!"));
		}
	}

	public List<AppRoleData> getApplicationMembersForRoleByKey(long roleKey) {
		return CdsSecurityAppRole.Retrieve(roleKey);
	}

	public List<GroupRoleData> getGroupMembersForRoleByKey(long roleKey) {
		return CdsSecurityGroupRole.Retrieve(roleKey);
	}

	public RoleData getRoleByKey(long docId) {
		return getRoleByKey(docId, true);
	}

	public RoleData getRoleByKey(long docId, boolean loadMembers) {
		return CdsSecurityRole.Retrieve(docId, loadMembers);
	}

	public List<RoleData> getRoleForApplicationByRoleName(String appId, String roleName) {
		throw new RuntimeException("Not Implemented");
	}

	public RoleData getRoleForApplicationByRoleName(String appId, String roleName, boolean loadMembers, boolean ldapAttribs, Bookmark bookmarkId) {
		return CdsSecurityRole.RetrieveByRoleName(roleName, appId, loadMembers, ldapAttribs, bookmarkId);
	}

	public List<UserRoleData> getRoleOwners(long roleKey) {
		throw new RuntimeException("Not Implemented");
	}

	public List<RoleData> getRolesForApplication(String appId) {
		return getRolesForApplication(appId, true);
	}

	public List<RoleData> getRolesForApplication(String appId, boolean loadMembers) {
		return CdsSecurityRole.RetrieveRolesForAdmin(appId, loadMembers, null);
	}

	public List<RoleData> getRolesForApplicationByPartialRoleName(String appId, String partRoleNm) {
		throw new RuntimeException("Not Implemented");
	}

	public List<RoleData> getRolesOfUser(String userId) {
		List<RoleData> roles = new ArrayList();
		List<Long> keys = new ArrayList();
		List<UserRoleData> userRoles = CdsSecurityUserRole.Retrieve(userId, false);
		LOGGER.info(new FedExLogEntry("List of Roles For User: " + userRoles.toString()));
		GrsUtils grsUtils = new GrsUtils();
		List<String> groups = grsUtils.getGroupsForUser(userId);
		LOGGER.info(new FedExLogEntry("List of Groups For User: " + groups.toString()));
		List<GroupRoleData> groupRoles = new ArrayList();
		if ((groups != null) && (!groups.isEmpty())) {
			for (String group : groups) {
				groupRoles.addAll(CdsSecurityGroupRole.Retrieve(group));
			}
		}
		LOGGER.info(new FedExLogEntry("List of Roles For Groups: " + groupRoles.toString()));
		for (UserRoleData userRole : userRoles) {
			keys.add(Long.valueOf(userRole.getRoleDocId()));
		}
		for (GroupRoleData groupRole : groupRoles) {
			keys.add(Long.valueOf(groupRole.getRoleDocId()));
		}
		if (!keys.isEmpty()) {
			roles = CdsSecurityRole.RetrieveAll(keys, false);
			LOGGER.info(new FedExLogEntry("Total List of Roles For User: " + roles.toString()));
		}
		return roles;
	}

	public List<RoleData> getManagingRolesOfUser(String userId) {
		List<RoleData> roles = new ArrayList();
		List<Long> keys = new ArrayList();
		List<UserRoleData> userRoles = CdsSecurityUserRole.Retrieve(userId, false);
		LOGGER.info(new FedExLogEntry("List of Roles For User: " + userRoles.toString()));
		GrsUtils grsUtils = new GrsUtils();
		List<String> groups = grsUtils.getGroupsForUser(userId);
		LOGGER.info(new FedExLogEntry("List of Groups For User: " + groups.toString()));
		List<GroupRoleData> groupRoles = new ArrayList();
		if ((groups != null) && (!groups.isEmpty())) {
			for (String group : groups) {
				groupRoles.addAll(CdsSecurityGroupRole.Retrieve(group));
			}
		}
		LOGGER.info(new FedExLogEntry("List of Roles For Groups: " + groupRoles.toString()));
		for (UserRoleData userRole : userRoles) {
			keys.add(Long.valueOf(userRole.getRoleDocId()));
		}
		for (GroupRoleData groupRole : groupRoles) {
			keys.add(Long.valueOf(groupRole.getRoleDocId()));
		}
		List<RoleData> finalRoles = new ArrayList();
		if (!keys.isEmpty()) {
			roles = CdsSecurityRole.RetrieveAll(keys, false, false);
			List<RoleData> escRoles;
			Iterator i$;
			if ((roles != null) && (!roles.isEmpty())) {
				escRoles = CdsSecurityRole.RetrieveByAppId("4112", false, false, new Bookmark());
				if ((escRoles != null) && (!escRoles.isEmpty())) {
					for (i$ = roles.iterator(); i$.hasNext(); ) {
						RoleData role = (RoleData)i$.next();
						for (RoleData escRole : escRoles) {
							if (role.getDocId() == escRole.getDocId()) {
								finalRoles.add(role);
								break;
							}
						}
					}
				}
			}
			LOGGER.info(new FedExLogEntry("Total List of Roles For User: " + finalRoles.toString()));
		}
		return finalRoles;
	}

	public RoleData getManagingRoleOfApplication(String appId) {
		long roleDocId = 0L;
		List<RuleData> rulesData = CdsSecurityRule.Retrieve("4112", new Bookmark());
		for (RuleData rule : rulesData) {
			if ((rule.getResourceNm().equals(appId)) && (rule.getActionNm().equals("*"))) {
				roleDocId = rule.getRoleDocId();
				LOGGER.info(new FedExLogEntry("get the role doc ID : " + roleDocId));
				break;
			}
		}
		RoleData role = getRoleByKey(roleDocId, true);
		return role;
	}

	public boolean isAppInManagingRole(String appId, String onBehalfOf) {
		boolean isAppInRole = false;
		RoleData role = getManagingRoleOfApplication(appId.concat("/*"));
		if ((role.getAppMemberList() != null) && (role.getAppMemberList().size() > 0)) {
			for (AppRoleData appRole : role.getAppMemberList()) {
				if (appRole.getAppId().trim().equals(onBehalfOf.trim())) {
					isAppInRole = true;
				}
			}
		}
		return isAppInRole;
	}

	public boolean isUserInManagingRole(String appId, String empId) {
		boolean isUserInRole = false;
		RoleData role = getManagingRoleOfApplication(appId.concat("/*"));
		LOGGER.info(new FedExLogEntry("isUserInManagingRole : " + role.toString()));
		if ((role.getUserMemberList() != null) && (role.getUserMemberList().size() > 0)) {
			for (UserRoleData userRole : role.getUserMemberList()) {
				if (userRole.getEmpNbr().equals(empId)) {
					isUserInRole = true;
					return isUserInRole;
				}
			}
		}
		GrsUtils grsUtils = new GrsUtils();
		List<String> groups = grsUtils.getGroupsForUser(empId);
		Iterator i$;
		if ((role.getGroupMemberList() != null) && (!role.getGroupMemberList().isEmpty()) && (!groups.isEmpty())) {
			for (i$ = role.getGroupMemberList().iterator(); i$.hasNext(); ) {
				GroupRoleData groupRole = (GroupRoleData)i$.next();
				for (String group : groups) {
					if (groupRole.getGroupNm().equals(group)) {
						isUserInRole = true;
					}
				}
			}
		}
		return isUserInRole;
	}

	public List<UserRoleData> getUserMembersForRoleByKey(long roleKey) {
		return CdsSecurityUserRole.Retrieve(roleKey);
	}

	public long insertRole(RoleData roleData) {
		return CdsSecurityRole.Insert(roleData);
	}

	public void updateRole(RoleData roleData) {
		CdsSecurityRole.Update(roleData);
	}

	public long updateRoleAppsForApplication(AppRoleData appRoleData, long roleDocId) {
		return CdsSecurityAppRole.Insert(appRoleData, roleDocId);
	}

	public long updateRoleGroupsForApplication(GroupRoleData groupRoleData, long roleDocId) {
		RoleData role = CdsSecurityRole.Retrieve(roleDocId);
		JmsAuditRecordUser jmsRecord = null;
		if ((role.getRoleScopeNm() != null) && (AuthorizorFactory.getAuthorizor().isAllowed(EscUtils.prependAPP(role.getRoleScopeNm()), "jms/GainOfAccessMessage/", "receive"))) {
			GrsUtils grsUtils = new GrsUtils();
			List<String> members = grsUtils.getMembersOfGroup(groupRoleData.getGroupNm());
			jmsRecord = new JmsAuditRecordUser();
			jmsRecord.setRoleName(role.getRoleNm());
			jmsRecord.setApplicationID(Long.parseLong(role.getRoleScopeNm()));
			jmsRecord.setEventTmstp(CdsSecurityBase.getStaticDateTime());
			jmsRecord.setGroupName(groupRoleData.getGroupNm());
			jmsRecord.setEventDesc(groupRoleData.getGroupNm() + " was added to " + role.getRoleNm());
			jmsRecord.setEventType(EventType.GROUP_ADDED_TO_ROLE);
			if (members.size() > 10000) {
				jmsRecord.setErrorDesc(groupRoleData.getGroupNm() + " exceeds max limit of 10,000 members");
			}
			else {
				for (String uid : members) {
					jmsRecord.getImpactedEmployeeID().add(uid);
				}
			}
		}
		else {
			if (LOGGER.infoEnabled()) {
				LOGGER.info(new FedExLogEntry("Sending GainOfAccess JMS Message for the application " + role.getRoleScopeNm() + " is not allowed"));
			}
		}
		long docId = CdsSecurityGroupRole.Insert(groupRoleData, roleDocId);
		if (jmsRecord != null) {
			this.gainOfAccessPublisher.publishMessage(jmsRecord);
		}
		return docId;
	}

	public long updateRoleGroupsForApplication(GroupRoleData groupRoleData, long roleDocId, boolean systemOverride, String onBehalfOf, String appId) {
		RoleData role = CdsSecurityRole.Retrieve(roleDocId);
		JmsAuditRecordUser jmsRecord = null;
		if ((role.getRoleScopeNm() != null) && (AuthorizorFactory.getAuthorizor().isAllowed(EscUtils.prependAPP(role.getRoleScopeNm()), "jms/GainOfAccessMessage/", "receive"))) {
			GrsUtils grsUtils = new GrsUtils();
			List<String> members = grsUtils.getMembersOfGroup(groupRoleData.getGroupNm());
			jmsRecord = new JmsAuditRecordUser();
			jmsRecord.setRoleName(role.getRoleNm());
			jmsRecord.setApplicationID(Long.parseLong(role.getRoleScopeNm()));
			jmsRecord.setEventTmstp(CdsSecurityBase.getStaticDateTime());
			jmsRecord.setGroupName(groupRoleData.getGroupNm());
			jmsRecord.setEventDesc(groupRoleData.getGroupNm() + " was added to " + role.getRoleNm());
			jmsRecord.setEventType(EventType.GROUP_ADDED_TO_ROLE);
			if (members.size() > 10000) {
				jmsRecord.setErrorDesc(groupRoleData.getGroupNm() + " exceeds max limit of 10,000 members");
			}
			else {
				for (String uid : members) {
					jmsRecord.getImpactedEmployeeID().add(uid);
				}
			}
		}
		else {
			if (LOGGER.infoEnabled()) {
				LOGGER.info(new FedExLogEntry("Sending GainOfAccess JMS Message for the application " + role.getRoleScopeNm() + " is not allowed"));
			}
		}
		long docId = CdsSecurityGroupRole.Insert(groupRoleData, roleDocId, systemOverride, onBehalfOf, appId);
		if (jmsRecord != null) {
			this.gainOfAccessPublisher.publishMessage(jmsRecord);
		}
		return docId;
	}

	public long updateRoleUsersForApplication(UserRoleData userRoleData, long roleDocId) {
		RoleData role = CdsSecurityRole.Retrieve(roleDocId);
		JmsAuditRecordUser jmsRecord = null;
		if ((role.getRoleScopeNm() != null) && (AuthorizorFactory.getAuthorizor().isAllowed(EscUtils.prependAPP(role.getRoleScopeNm()), "jms/GainOfAccessMessage/", "receive"))) {
			jmsRecord = new JmsAuditRecordUser();
			jmsRecord.setRoleName(role.getRoleNm());
			jmsRecord.setEventTmstp(CdsSecurityBase.getStaticDateTime());
			jmsRecord.getImpactedEmployeeID().add(userRoleData.getEmpNbr());
			jmsRecord.setApplicationID(Long.parseLong(role.getRoleScopeNm()));
			jmsRecord.setEventType(EventType.USER_ADDED_TO_ROLE);
			jmsRecord.setEventDesc(userRoleData.getEmpNbr() + " was added to " + role.getRoleNm());
		}
		else {
			if (LOGGER.infoEnabled()) {
				LOGGER.info(new FedExLogEntry("Sending GainOfAccess JMS Message for the application " + role.getRoleScopeNm() + " is not allowed"));
			}
		}
		long docId = CdsSecurityUserRole.Insert(userRoleData, roleDocId);
		if (jmsRecord != null) {
			this.gainOfAccessPublisher.publishMessage(jmsRecord);
		}
		return docId;
	}

	public long updateRoleUsersForApplication(UserRoleData userRoleData, long roleDocId, boolean systemOverride, String onBehalfOf, String appId) {
		RoleData role = CdsSecurityRole.Retrieve(roleDocId);
		JmsAuditRecordUser jmsRecord = null;
		if ((role.getRoleScopeNm() != null) && (AuthorizorFactory.getAuthorizor().isAllowed(EscUtils.prependAPP(role.getRoleScopeNm()), "jms/GainOfAccessMessage/", "receive"))) {
			jmsRecord = new JmsAuditRecordUser();
			jmsRecord.setRoleName(role.getRoleNm());
			jmsRecord.setEventTmstp(CdsSecurityBase.getStaticDateTime());
			jmsRecord.getImpactedEmployeeID().add(userRoleData.getEmpNbr());
			jmsRecord.setApplicationID(Long.parseLong(role.getRoleScopeNm()));
			jmsRecord.setEventType(EventType.USER_ADDED_TO_ROLE);
			jmsRecord.setEventDesc(userRoleData.getEmpNbr() + " was added to " + role.getRoleNm());
		}
		else {
			if (LOGGER.infoEnabled()) {
				LOGGER.info(new FedExLogEntry("Sending GainOfAccess JMS Message for the application " + role.getRoleScopeNm() + " is not allowed"));
			}
		}
		long docId = CdsSecurityUserRole.Insert(userRoleData, roleDocId, systemOverride, onBehalfOf, appId);
		if (jmsRecord != null) {
			this.gainOfAccessPublisher.publishMessage(jmsRecord);
		}
		return docId;
	}

	public long insertRestriction(RestrictionData restriction) {
		return insertRestriction(restriction, false);
	}

	public long insertRestriction(RestrictionData restriction, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		try {
			if ((!systemOverride) && (FacesContext.getCurrentInstance() != null)) {
				WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
				onBehalfOf = roleHandler.getUserId();
			}
		}
		catch (SOAPFaultException sfe) {
			throw new RuntimeException(sfe.getMessage(), sfe);
		}
		return insertRestriction(restriction, systemOverride, onBehalfOf, "");
	}

	public long insertRestriction(RestrictionData restriction, boolean systemOverride, String onBehalfOf, String appId) {
		JmsAuditRecordUser jmsRecord = null;
		if ((restriction.getAppId() != null) && (AuthorizorFactory.getAuthorizor().isAllowed(EscUtils.prependAPP(restriction.getAppId()), "jms/LossOfAccessMessage/", "receive"))) {
			jmsRecord = new JmsAuditRecordUser();
			jmsRecord.setRoleName(restriction.getRoleNm());
			jmsRecord.setEventTmstp(CdsSecurityBase.getStaticDateTime());
			if (!EscUtils.isNullOrBlank(restriction.getEmplId())) {
				jmsRecord.getImpactedEmployeeID().add(restriction.getEmplId());
				jmsRecord.setEventDesc(restriction.getEmplId() + " loss full access to the role: " + restriction.getRoleNm() + " due to restriction(s) being added to the user");
				jmsRecord.setEventType(EventType.RESTRICTION_ADDED_TO_USER);
			}
			else {
				GrsUtils grsUtils = new GrsUtils();
				List<String> members = grsUtils.getMembersOfGroup(restriction.getGroupNm());
				if (members.size() > 10000) {
					jmsRecord.setErrorDesc(restriction.getGroupNm() + " exceeds max limit of 10,000 members");
				}
				else {
					for (String uid : members) {
						jmsRecord.getImpactedEmployeeID().add(uid);
					}
					jmsRecord.setEventDesc(restriction.getGroupNm() + " loss full access to the role: " + restriction.getRoleNm() + " due to restriction(s) being added to the group");
				}
				jmsRecord.setEventType(EventType.RESTRICTION_ADDED_TO_GROUP);
			}
			jmsRecord.setApplicationID(Long.parseLong(restriction.getAppId()));
		}
		else {
			if (LOGGER.infoEnabled()) {
				LOGGER.info(new FedExLogEntry("Sending LossOfAccess JMS Message for the application " + restriction.getAppId() + " is not allowed"));
			}
		}
		long success = 0L;
		success = CdsSecurityRestriction.InsertRestriction(restriction, systemOverride, onBehalfOf, restriction.getAppId());
		if (success > 0L) {
			if (jmsRecord != null) {
				this.securityPublisher.publishMessage(jmsRecord);
			}
		}
		else {
			LOGGER.warn(new FedExLogEntry("Failed to send JMS Message loss of access because the restriction was not successfully inserted."));
		}
		return success;
	}

	public void deleteRestriction(RestrictionData restriction) {
		deleteRestriction(restriction, false);
	}

	public void deleteRestriction(RestrictionData restriction, boolean systemOverride) {
		String onBehalfOf = "APP4112";
		try {
			if ((!systemOverride) && (FacesContext.getCurrentInstance() != null)) {
				WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
				onBehalfOf = roleHandler.getUserId();
			}
		}
		catch (SOAPFaultException sfe) {
			throw new RuntimeException(sfe.getMessage(), sfe);
		}
		deleteRestriction(restriction, systemOverride, onBehalfOf, "");
	}

	public void deleteRestriction(RestrictionData restriction, boolean systemOverride, String onBehalfOf, String appId) {
		JmsAuditRecordUser jmsRecord = null;
		if ((restriction.getAppId() != null) && (AuthorizorFactory.getAuthorizor().isAllowed(EscUtils.prependAPP(restriction.getAppId()), "jms/GainOfAccessMessage/", "receive"))) {
			jmsRecord = new JmsAuditRecordUser();
			jmsRecord.setRoleName(restriction.getRoleNm());
			jmsRecord.setEventTmstp(CdsSecurityBase.getStaticDateTime());
			if (!EscUtils.isNullOrBlank(restriction.getEmplId())) {
				jmsRecord.getImpactedEmployeeID().add(restriction.getEmplId());
				jmsRecord.setEventDesc(restriction.getEmplId() + " gained full access to the role: " + restriction.getRoleNm() + " due to restriction(s) being removed from the user.");
				jmsRecord.setEventType(EventType.RESTRICTION_REMOVED_FROM_USER);
			}
			else {
				GrsUtils grsUtils = new GrsUtils();
				List<String> members = grsUtils.getMembersOfGroup(restriction.getGroupNm());
				if (members.size() > 10000) {
					jmsRecord.setErrorDesc(restriction.getGroupNm() + " exceeds max limit of 10,000 members");
				}
				else {
					for (String uid : members) {
						jmsRecord.getImpactedEmployeeID().add(uid);
					}
					jmsRecord.setEventDesc(restriction.getGroupNm() + " gained access to the role: " + restriction.getRoleNm() + " due to restriction(s) being removed  from the group.");
				}
				jmsRecord.setEventType(EventType.RESTRICTION_REMOVED_FROM_GROUP);
			}
			jmsRecord.setApplicationID(Long.parseLong(restriction.getAppId()));
		}
		else {
			if (LOGGER.infoEnabled()) {
				LOGGER.info(new FedExLogEntry("Sending GainOfAccess JMS Message for the application " + restriction.getAppId() + " is not allowed"));
			}
		}
		CdsSecurityRestriction.DeleteRestriction(restriction, systemOverride, onBehalfOf, appId);
		if (jmsRecord != null) {
			this.gainOfAccessPublisher.publishMessage(jmsRecord);
		}
	}

	public List<RestrictionData> getRestrictionsForApplication(String appId, Bookmark bookmarkId) {
		return CdsSecurityRestriction.RetrieveRoleRestrictions(bookmarkId, appId);
	}

	public List<RestrictionData> getRestrictionsForRole(String appId, String roleName, Bookmark bookmarkId) {
		return CdsSecurityRestriction.RetrieveRestrictionsByRoleName(appId, roleName, bookmarkId);
	}

	public List<RestrictionData> getRestrictionsForUserOrGrp(String appId, String roleName, String userId) {
		return CdsSecurityRestriction.RetrieveRestrictionsByRoleNameEmpId(appId, roleName, userId);
	}

	public RestrictionData restrieveRestrictionByKey(long docId) {
		return CdsSecurityRestriction.retrieveRestrictionByKey(docId);
	}

	public String retrieveSingleSequence() {
		return CdsSecurityRestriction.requestSingleSequence();
	}

	public RestrictionSequence retrieveMultipleSequences(int blockSize) {
		return CdsSecurityRestriction.requestMultipleSequences(blockSize);
	}

	public CompositeResponse updateRestriction(RestrictionData restrictionData) {
		return CdsSecurityRestriction.UpdateRestriction(restrictionData);
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\role\RoleServiceImpl.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */