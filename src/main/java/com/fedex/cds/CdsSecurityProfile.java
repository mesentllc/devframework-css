package com.fedex.cds;

import com.fedex.ea.framework.securityapi.dao.esc.EscDaoException;
import com.fedex.enterprise.security.action.ActionData;
import com.fedex.enterprise.security.customauthz.CustomAuthzData;
import com.fedex.enterprise.security.resource.ResourceData;
import com.fedex.enterprise.security.role.AppRoleData;
import com.fedex.enterprise.security.role.GroupRoleData;
import com.fedex.enterprise.security.role.RoleData;
import com.fedex.enterprise.security.role.UserRoleData;
import com.fedex.enterprise.security.role.restriction.RestrictionData;
import com.fedex.enterprise.security.rule.ExtendedRuleData;
import com.fedex.enterprise.security.rule.ExtendedRuleXrefData;
import com.fedex.enterprise.security.rule.RuleData;
import com.fedex.enterprise.security.utils.SecurityDataBaseClass;
import com.fedex.framework.cds.IndexQueryRequest;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CdsSecurityProfile
		extends CdsSecurityBase {
	private static final String EXISTS_IN_CDS_BUT_THE_ROLE_IS_NOT_FOUND_IN_CDS = " exists in CDS, but the role is not found in CDS";
	private static final FedExLoggerInterface LOGGER = FedExLogger.getLogger(CdsSecurityProfile.class);

	public ProfileData retrieveProfile(String appId)
			throws EscDaoException {
		Map<Long, ActionData> mapActions = new HashMap();
		Map<Long, RoleData> mapRoles = new HashMap();
		Map<Long, RuleData> mapRules = new HashMap();
		Map<Long, ResourceData> mapResource = new HashMap();
		Map<Long, ExtendedRuleData> mapExtendedRule = new HashMap();
		Map<Long, CustomAuthzData> mapCustomAuthorizer = new HashMap();
		ProfileData profileData = new ProfileData();
		IndexQueryRequest.QueryItem actionQueryItem = CdsClient.createIndexQueryItem("/action/@ApplicationId", CdsClient.QUERY_COMPARE.equals, appId, "authZ", CdsSecurityBase.STANZAS.action, "authZ", CdsSecurityBase.STANZAS.action);
		IndexQueryRequest.QueryItem customAuthorizerQueryItem = CdsClient.createIndexQueryItem("/customAuthZClass/@ApplicationId", CdsClient.QUERY_COMPARE.equals, appId, "authZ", CdsSecurityBase.STANZAS.customAuthZClass, "authZ", CdsSecurityBase.STANZAS.customAuthZClass);
		IndexQueryRequest.QueryItem extendedRuleQueryItem = CdsClient.createIndexQueryItem("/extendedRule/@ApplicationId", CdsClient.QUERY_COMPARE.equals, appId, "authZ", CdsSecurityBase.STANZAS.extendedRule, "authZ", CdsSecurityBase.STANZAS.extendedRule);
		IndexQueryRequest.QueryItem extRuleXrefQueryItem = CdsClient.createIndexQueryItem("/extRuleXRef/@ApplicationId", CdsClient.QUERY_COMPARE.equals, appId, "authZ", CdsSecurityBase.STANZAS.extRuleXRef, "authZ", CdsSecurityBase.STANZAS.extRuleXRef);
		IndexQueryRequest.QueryItem resourceQueryItem = CdsClient.createIndexQueryItem("/resource/@ApplicationId", CdsClient.QUERY_COMPARE.equals, appId, "authZ", CdsSecurityBase.STANZAS.resource, "authZ", CdsSecurityBase.STANZAS.resource);
		IndexQueryRequest.QueryItem ruleQueryItem = CdsClient.createIndexQueryItem("/rule/@ApplicationId", CdsClient.QUERY_COMPARE.equals, appId, "authZ", CdsSecurityBase.STANZAS.rule, "authZ", CdsSecurityBase.STANZAS.rule);
		IndexQueryRequest.QueryItem roleQueryItem = CdsClient.createIndexQueryItem("/role/@RoleScopeName", CdsClient.QUERY_COMPARE.equals, appId, "authZ", CdsSecurityBase.STANZAS.role, "authZ", CdsSecurityBase.STANZAS.role);
		IndexQueryRequest.QueryItem appRoleQueryItem = CdsClient.createIndexQueryItem("/role/@RoleScopeName", CdsClient.QUERY_COMPARE.equals, appId, "authZ", CdsSecurityBase.STANZAS.role, "authZ", CdsSecurityBase.STANZAS.applicationRole);
		IndexQueryRequest.QueryItem groupRoleQueryItem = CdsClient.createIndexQueryItem("/role/@RoleScopeName", CdsClient.QUERY_COMPARE.equals, appId, "authZ", CdsSecurityBase.STANZAS.role, "authZ", CdsSecurityBase.STANZAS.groupRole);
		IndexQueryRequest.QueryItem userRoleQueryItem = CdsClient.createIndexQueryItem("/role/@RoleScopeName", CdsClient.QUERY_COMPARE.equals, appId, "authZ", CdsSecurityBase.STANZAS.role, "authZ", CdsSecurityBase.STANZAS.userRole);
		IndexQueryRequest.QueryItem restrictionRoleQueryItem = CdsClient.createIndexQueryItem("/restriction/APPID", CdsClient.QUERY_COMPARE.equals, appId, "authZ", CdsSecurityBase.STANZAS.restriction, "authZ", CdsSecurityBase.STANZAS.restriction);
		IndexQueryRequest indexQueryRequest = CdsClient.createIndexQuery(new ArrayList(Arrays.asList(resourceQueryItem, actionQueryItem, ruleQueryItem, restrictionRoleQueryItem, extendedRuleQueryItem, extRuleXrefQueryItem, customAuthorizerQueryItem, roleQueryItem, appRoleQueryItem, groupRoleQueryItem, userRoleQueryItem)));
		List<SecurityDataBaseClass> dataList = cdsClient.indexQuery(indexQueryRequest, true);
		for (SecurityDataBaseClass data : dataList) {
			mapData(SecurityDataBaseClass.DATA_TYPE.ROLE, data, mapRoles, profileData.getRoleList());
			mapData(SecurityDataBaseClass.DATA_TYPE.ACTION, data, mapActions, profileData.getActionList());
			mapData(SecurityDataBaseClass.DATA_TYPE.RULE, data, mapRules, profileData.getRuleList());
			mapData(SecurityDataBaseClass.DATA_TYPE.RESOURCE, data, mapResource, profileData.getResourceList());
			mapData(SecurityDataBaseClass.DATA_TYPE.EXTENDED_RULE, data, mapExtendedRule, profileData.getExtendedRuleList());
			mapData(SecurityDataBaseClass.DATA_TYPE.CUSTOM_AUTHZ, data, mapCustomAuthorizer, profileData.getCustomAuthorizerList());
		}
		for (SecurityDataBaseClass data : dataList) {
			if (SecurityDataBaseClass.DATA_TYPE.APP_ROLE.equals(data.getDataType())) {
				AppRoleData appRole = (AppRoleData)data;
				if (mapRoles.containsKey(Long.valueOf(appRole.getRoleDocId()))) {
					mapRoles.get(Long.valueOf(appRole.getRoleDocId())).getAppMemberList().add(appRole);
				}
				else {
					LOGGER.always("The application role " + appRole.getAppId() + " exists in CDS, but the role is not found in CDS");
				}
			}
			else {
				if (SecurityDataBaseClass.DATA_TYPE.GROUP_ROLE.equals(data.getDataType())) {
					GroupRoleData groupRole = (GroupRoleData)data;
					if (mapRoles.containsKey(Long.valueOf(groupRole.getRoleDocId()))) {
						mapRoles.get(Long.valueOf(groupRole.getRoleDocId())).getGroupMemberList().add(groupRole);
					}
					else {
						LOGGER.always("The group role " + groupRole.getGroupNm() + " exists in CDS, but the role is not found in CDS");
					}
				}
				else {
					if (SecurityDataBaseClass.DATA_TYPE.USER_ROLE.equals(data.getDataType())) {
						UserRoleData userRole = (UserRoleData)data;
						if (mapRoles.containsKey(Long.valueOf(userRole.getRoleDocId()))) {
							mapRoles.get(Long.valueOf(userRole.getRoleDocId())).getUserMemberList().add(userRole);
						}
						else {
							LOGGER.always("The user role " + userRole.getEmpNbr() + " exists in CDS, but the role is not found in CDS");
						}
					}
					else {
						if (SecurityDataBaseClass.DATA_TYPE.RESTRICTION.equals(data.getDataType())) {
							RestrictionData restriction = (RestrictionData)data;
							if (mapRoles.containsKey(Long.valueOf(restriction.getRoleDocId()))) {
								mapRoles.get(Long.valueOf(restriction.getRoleDocId())).getRestrictionMemberList().add(restriction);
							}
							else {
								LOGGER.always("The restriction " + restriction.toString() + " exists in CDS, but the role is not found in CDS");
							}
						}
						else {
							if (SecurityDataBaseClass.DATA_TYPE.EXTENDED_RULE_XREF.equals(data.getDataType())) {
								ExtendedRuleXrefData xref = (ExtendedRuleXrefData)data;
								RuleData rule = mapRules.get(Long.valueOf(xref.getRuleDocId()));
								ExtendedRuleData extRule = mapExtendedRule.get(Long.valueOf(xref.getExtRuleDocId()));
								if ((rule != null) && (extRule != null)) {
									rule.getExtendedRuleList().add(extRule);
								}
								else {
									if (rule == null) {
										LOGGER.always("The cross reference for a rule and extended rule exists in CDS, but the rule does not exist: " + xref.toString());
									}
									if (extRule == null) {
										LOGGER.always("The cross reference for a rule and extended rule exists in CDS, but the extended rule does not exist: " + xref.toString());
									}
								}
							}
						}
					}
				}
			}
		}
		for (RuleData rule : mapRules.values()) {
			if (rule.getCustAuthZDocId() != 0L) {
				CustomAuthzData customAuthz = mapCustomAuthorizer.get(Long.valueOf(rule.getCustAuthZDocId()));
				if (customAuthz != null) {
					rule.setCustAuthZClassNm(customAuthz.getClassNm());
					rule.setCustAuthzExist(true);
				}
				else {
					LOGGER.always("A rule in CDS expects a custom authorizor (" + rule.getCustAuthZDocId() + ") but the custom authorizor was not found in CDS");
				}
			}
			RoleData role = mapRoles.get(Long.valueOf(rule.getRoleDocId()));
			if (role != null) {
				rule.setRoleNm(role.getRoleNm());
			}
			else {
				LOGGER.always("A rule exists in CDS but the Role (" + rule.getRoleDocId() + ") associated to it is not found in CDS");
			}
			ActionData action = mapActions.get(Long.valueOf(rule.getActionDocId()));
			if (action != null) {
				rule.setActionNm(action.getActionNm());
			}
			else {
				LOGGER.always("A rule exists in CDS but the action (" + rule.getActionDocId() + ") associated to it is not found in CDS");
			}
			ResourceData resource = mapResource.get(Long.valueOf(rule.getResDocId()));
			if (resource != null) {
				rule.setResourceNm(resource.getResName());
			}
			else {
				LOGGER.always("A rule exists in CDS but the resource (" + rule.getResDocId() + ") associated to it is not found in CDS");
			}
		}
		return profileData;
	}

	private <T extends SecurityDataBaseClass> void mapData(SecurityDataBaseClass.DATA_TYPE cdsDataType, SecurityDataBaseClass baseData, Map<Long, T> mapData, List<T> listData) {
		if (cdsDataType.equals(baseData.getDataType())) {
			mapData.put(Long.valueOf(baseData.getDocId()), (T)baseData);
			listData.add((T)baseData);
		}
	}

	public static class ProfileData {
		List<RoleData> roleList = new ArrayList();
		List<ActionData> actionList = new ArrayList();
		List<RuleData> ruleList = new ArrayList();
		List<ResourceData> resourceList = new ArrayList();
		List<ExtendedRuleData> extendedRuleList = new ArrayList();
		List<CustomAuthzData> customAuthorizerList = new ArrayList();

		public List<RoleData> getRoleList() {
			return this.roleList;
		}

		public List<ActionData> getActionList() {
			return this.actionList;
		}

		public List<RuleData> getRuleList() {
			return this.ruleList;
		}

		public List<ResourceData> getResourceList() {
			return this.resourceList;
		}

		public List<ExtendedRuleData> getExtendedRuleList() {
			return this.extendedRuleList;
		}

		public List<CustomAuthzData> getCustomAuthorizerList() {
			return this.customAuthorizerList;
		}
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\cds\CdsSecurityProfile.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */