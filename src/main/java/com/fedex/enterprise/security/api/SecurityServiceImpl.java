package com.fedex.enterprise.security.api;

import com.fedex.cds.CdsSecurityAction;
import com.fedex.cds.CdsSecurityCustomAuthorizer;
import com.fedex.cds.CdsSecurityExtRuleXRef;
import com.fedex.cds.CdsSecurityExtendedRule;
import com.fedex.cds.CdsSecurityResource;
import com.fedex.cds.CdsSecurityRestriction;
import com.fedex.cds.CdsSecurityRole;
import com.fedex.cds.CdsSecurityRule;
import com.fedex.ea.framework.securityapi.dao.esc.EscDaoException;
import com.fedex.enterprise.security.customauthz.CustomAuthzData;
import com.fedex.enterprise.security.resource.ResourceData;
import com.fedex.enterprise.security.role.RoleData;
import com.fedex.enterprise.security.role.restriction.RestrictionData;
import com.fedex.enterprise.security.rule.ExtendedRuleData;
import com.fedex.enterprise.security.rule.ExtendedRuleXrefData;
import com.fedex.enterprise.security.rule.RuleData;
import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import org.springframework.ws.soap.saaj.SaajSoapMessageException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

public class SecurityServiceImpl
		implements SecurityService {
	private static final String FOUND = "Found ";
	private static final String EXCEPTION_FROM_DATASTORE = "Exception from datastore: ";
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(SecurityServiceImpl.class);

	public List<RoleData> getRolesForApplicationAPI(String appId) {
		throw new RuntimeException("Please call getAllRolesForApplicationAPI(List<Long> roleDocIds) instead.");
	}

	public List<RuleData> getRulesForApplicationAPI(String appId) {
		try {
			List<RuleData> rules = new ArrayList();
			logger.warn(new FedExLogEntry("Time to get the rules from CDS for app id " + appId + "..."));
			Map<Long, RuleData> ruleMap = getRulesFromCDS(appId);
			if ((ruleMap != null) && (!ruleMap.isEmpty())) {
				logger.info(new FedExLogEntry("Time to get the extended rules from CDS..."));
				ruleMap = populateExtendedRules(ruleMap, appId);
				logger.info(new FedExLogEntry("Time to get the custom authorizers from CDS..."));
				ruleMap = populateCustomAuthorizers(ruleMap, appId);
				ruleMap = populateActionNames(ruleMap);
				ruleMap = populateResourceNames(ruleMap);
				ruleMap = populateRoleNames(ruleMap);
				for (Map.Entry<Long, RuleData> entry : ruleMap.entrySet()) {
					rules.add(entry.getValue());
				}
			}
			return rules;
		}
		catch (SaajSoapMessageException e) {
			String message = e.getMessage();
			if (message.startsWith("Could not write message to OutputStream")) {
				logger.warn(new FedExLogEntry("Timer Thread from Security API couldn't find ClassLoader, probably from a hot deploy, shutting down old timer..."));
				throw new RuntimeException("Old thread, time to put down.", e);
			}
			logger.warn(new FedExLogEntry("Exception from datastore: "), e);
			return null;
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Exception from datastore: "), e);
		}
		return null;
	}

	public List<RuleData> getRulesForApplicationAPIEnhanced(String appId) {
		try {
			List<RuleData> rules = new ArrayList();
			logger.warn(new FedExLogEntry("Time to get the rules from CDS for app id " + appId + "..."));
			Map<Long, RuleData> ruleMap = getRulesFromCDSEnhanced(appId);
			if ((ruleMap != null) && (!ruleMap.isEmpty())) {
				for (Map.Entry<Long, RuleData> entry : ruleMap.entrySet()) {
					rules.add(entry.getValue());
				}
			}
			return rules;
		}
		catch (SaajSoapMessageException e) {
			String message = e.getMessage();
			if (message.startsWith("Could not write message to OutputStream")) {
				logger.warn(new FedExLogEntry("Timer Thread from Security API couldn't find ClassLoader, probably from a hot deploy, shutting down old timer..."));
				throw new RuntimeException("Old thread, time to put down.", e);
			}
			logger.warn(new FedExLogEntry("Exception from datastore: "), e);
			return null;
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Exception from datastore: "), e);
		}
		return null;
	}

	public List<RoleData> getAllRolesForApplicationAPI(List<Long> roleDocIds, String appId) {
		try {
			return CdsSecurityRole.retrieveWithChildrenWithoutRestrictions(roleDocIds, appId, true);
		}
		catch (EscDaoException e) {
			logger.always("Unable to retrieve roles for rules.", e);
		}
		return null;
	}

	private Map<Long, RuleData> getRulesFromCDS(String appId)
			throws EscDaoException {
		Map<Long, RuleData> rules = new HashMap();
		List<RuleData> rulesArray = null;
		rulesArray = CdsSecurityRule.retrieveForApplication(appId, true);
		if ((rulesArray != null) && (!rulesArray.isEmpty())) {
			logger.warn(new FedExLogEntry("Found " + rulesArray.size() + " rules for app id " + appId));
		}
		else {
			logger.warn(new FedExLogEntry("No rules were found for app id " + appId));
		}
		for (RuleData rule : rulesArray) {
			rules.put(Long.valueOf(rule.getDocId()), rule);
		}
		return rules;
	}

	private Map<Long, RuleData> getRulesFromCDSEnhanced(String appId) {
		Map<Long, RuleData> rules = new HashMap();
		List<RuleData> rulesArray = CdsSecurityRule.RetrieveByNames(appId);
		if (rulesArray != null) {
			logger.warn(new FedExLogEntry("Found " + rulesArray.size() + " rules for app id " + appId));
		}
		else {
			logger.warn(new FedExLogEntry("No rules were found for app id " + appId));
		}
		for (RuleData rule : rulesArray) {
			rules.put(Long.valueOf(rule.getDocId()), rule);
		}
		return rules;
	}

	private Map<Long, RuleData> populateExtendedRules(Map<Long, RuleData> ruleMap, String appId)
			throws EscDaoException {
		List<ExtendedRuleXrefData> extendedRuleXref = CdsSecurityExtRuleXRef.retrieveForApplication(appId, true);
		Map<Long, ExtendedRuleData> mapExtRule;
		if ((extendedRuleXref != null) && (!extendedRuleXref.isEmpty())) {
			Set<Long> xrefKeys = new HashSet();
			for (ExtendedRuleXrefData xref : extendedRuleXref) {
				xrefKeys.add(Long.valueOf(xref.getExtRuleDocId()));
			}
			List<Long> xrefKeysList = new ArrayList(xrefKeys);
			List<ExtendedRuleData> xrefDataList = CdsSecurityExtendedRule.retrieve(xrefKeysList, true);
			mapExtRule = new HashMap();
			for (ExtendedRuleData xrefData : xrefDataList) {
				mapExtRule.put(Long.valueOf(xrefData.getDocId()), xrefData);
			}
			for (ExtendedRuleXrefData xref : extendedRuleXref) {
				if (ruleMap.containsKey(Long.valueOf(xref.getRuleDocId()))) {
					if (mapExtRule.containsKey(Long.valueOf(xref.getExtRuleDocId()))) {
						RuleData ruleData = ruleMap.get(Long.valueOf(xref.getRuleDocId()));
						ExtendedRuleData extendedRuleData = mapExtRule.get(Long.valueOf(xref.getExtRuleDocId()));
						if (ruleData.getExtendedRuleList() == null) {
							ruleData.setExtendedRuleList(new ArrayList());
							ruleData.setExtdRuleExist(true);
						}
						ruleData.getExtendedRuleList().add(extendedRuleData);
					}
					else {
						logger.always("Data Integrety Issue: Extended rule cross reference " + xref.getDocId() + " exists, but extended rule " + xref.getExtRuleDocId() + "does not.");
					}
				}
				else {
					logger.always("Data Integrety Issue: Extended rule cross reference " + xref.getDocId() + " exists, but rule " + xref.getRuleDocId() + "does not.");
				}
			}
		}
		return ruleMap;
	}

	private Map<Long, RuleData> populateCustomAuthorizers(Map<Long, RuleData> ruleMap, String appId)
			throws EscDaoException {
		Set<Long> custAuthIdSet = new HashSet();
		for (Map.Entry<Long, RuleData> rule : ruleMap.entrySet()) {
			if (rule.getValue().getCustAuthZDocId() != 0L) {
				custAuthIdSet.add(Long.valueOf(rule.getValue().getCustAuthZDocId()));
			}
		}
		if (custAuthIdSet.isEmpty()) {
			return ruleMap;
		}
		List<CustomAuthzData> custAuthzList = CdsSecurityCustomAuthorizer.retrieve(new ArrayList(custAuthIdSet), true);
		Map<Long, CustomAuthzData> custAuthzMap;
		if ((custAuthzList != null) && (!custAuthzList.isEmpty())) {
			custAuthzMap = new HashMap(custAuthzList.size());
			for (CustomAuthzData custAuthz : custAuthzList) {
				custAuthzMap.put(Long.valueOf(custAuthz.getDocId()), custAuthz);
			}
			for (Map.Entry<Long, RuleData> rule : ruleMap.entrySet()) {
				if (rule.getValue().getCustAuthZDocId() != 0L) {
					if (custAuthzMap.containsKey(Long.valueOf(rule.getValue().getCustAuthZDocId()))) {
						CustomAuthzData customAuthz = custAuthzMap.get(Long.valueOf(rule.getValue().getCustAuthZDocId()));
						List<CustomAuthzData> custAuthzList2 = new ArrayList();
						rule.getValue().setCustAuthZDocId(customAuthz.getDocId());
						rule.getValue().setCustAuthZClassNm(customAuthz.getClassNm());
						custAuthzList2.add(customAuthz);
						rule.getValue().setCustAuthzList(custAuthzList2);
					}
					else {
						logger.always("Data Integrety Issue: Rule " + rule.getValue().getDocId() + " has a custom authorizer " + rule.getValue().getCustAuthZDocId() + " that was not found.");
					}
				}
			}
		}
		return ruleMap;
	}

	private Map<Long, RuleData> populateActionNames(Map<Long, RuleData> ruleMap)
			throws EscDaoException {
		List<Long> keys = new ArrayList();
		TreeSet<Long> treeSet = new TreeSet();
		for (Map.Entry<Long, RuleData> rule : ruleMap.entrySet()) {
			treeSet.add(Long.valueOf(rule.getValue().getActionDocId()));
		}
		keys.addAll(treeSet);
		logger.warn(new FedExLogEntry("Found " + keys.size() + " unique Action names."));
		Map<Long, String> actionList = CdsSecurityAction.retrieveNames(keys);
		for (Map.Entry<Long, RuleData> rule : ruleMap.entrySet()) {
			if (actionList.containsKey(Long.valueOf(rule.getValue().getActionDocId()))) {
				rule.getValue().setActionNm(actionList.get(Long.valueOf(rule.getValue().getActionDocId())));
			}
			else {
				logger.always("Data Integrity Error: Rule " + rule.getKey() + " exists where the action " + rule.getValue().getActionDocId() + " does not.");
			}
		}
		return ruleMap;
	}

	private Map<Long, RuleData> populateResourceNames(Map<Long, RuleData> ruleMap)
			throws EscDaoException {
		List<Long> keys = new ArrayList();
		TreeSet<Long> treeSet = new TreeSet();
		for (Map.Entry<Long, RuleData> rule : ruleMap.entrySet()) {
			treeSet.add(Long.valueOf(rule.getValue().getResDocId()));
		}
		keys.addAll(treeSet);
		logger.warn(new FedExLogEntry("Found " + keys.size() + " unique Resource names."));
		Map<Long, String> resourceList = CdsSecurityResource.retrieveNames(keys);
		for (Map.Entry<Long, RuleData> rule : ruleMap.entrySet()) {
			if (resourceList.containsKey(Long.valueOf(rule.getValue().getResDocId()))) {
				rule.getValue().setResourceNm(resourceList.get(Long.valueOf(rule.getValue().getResDocId())));
			}
			else {
				logger.always("Data Integrity Error: Rule " + rule.getKey() + " exists where the resource " + rule.getValue().getResDocId() + " does not.");
			}
		}
		return ruleMap;
	}

	private Map<Long, RuleData> populateRoleNames(Map<Long, RuleData> ruleMap)
			throws EscDaoException {
		List<Long> keys = new ArrayList();
		TreeSet<Long> treeSet = new TreeSet();
		for (Map.Entry<Long, RuleData> rule : ruleMap.entrySet()) {
			treeSet.add(Long.valueOf(rule.getValue().getRoleDocId()));
		}
		keys.addAll(treeSet);
		logger.warn(new FedExLogEntry("Found " + keys.size() + " unique Role names."));
		Map<Long, String> roleList = CdsSecurityRole.retrieveNames(keys);
		for (Map.Entry<Long, RuleData> rule : ruleMap.entrySet()) {
			if (roleList.containsKey(Long.valueOf(rule.getValue().getRoleDocId()))) {
				rule.getValue().setRoleNm(roleList.get(Long.valueOf(rule.getValue().getRoleDocId())));
			}
			else {
				logger.always("Data Integrity Error: Rule " + rule.getKey() + " exists where the role " + rule.getValue().getRoleDocId() + " does not.");
			}
		}
		return ruleMap;
	}

	public List<RestrictionData> getRestrictionsOnRoles(String appId) {
		return CdsSecurityRestriction.RetrieveRoleRestrictions(null, appId);
	}

	public List<RoleData> getRolesFromCDSEnhanced(String appId) {
		try {
			return CdsSecurityRole.RetrieveByNames(appId);
		}
		catch (Exception e) {
			logger.error(new FedExLogEntry("Exception from datastore: "), e);
		}
		return null;
	}

	public List<ResourceData> getResourcesFromCDS(String appId) {
		try {
			return CdsSecurityResource.RetrieveByNames(appId);
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Exception from datastore: "), e);
		}
		return null;
	}

	public List<ResourceData> getRootResourcesFromCDS(String appId) {
		try {
			return CdsSecurityResource.RetrieveRootResourcesByNames(appId);
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Exception from datastore: "), e);
		}
		return null;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\api\SecurityServiceImpl.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */