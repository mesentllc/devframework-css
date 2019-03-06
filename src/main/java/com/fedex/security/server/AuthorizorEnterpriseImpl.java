package com.fedex.security.server;

import com.fedex.enterprise.security.role.restriction.Entry;
import com.fedex.enterprise.security.role.restriction.RestrictionData;
import com.fedex.enterprise.security.role.restriction.RestrictionDataItem;
import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import com.fedex.security.exceptions.NullEntryListException;
import com.fedex.security.exceptions.SecurityConfigurationException;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class AuthorizorEnterpriseImpl
		implements Authorizor {
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(AuthorizorEnterpriseImpl.class.getName());
	private static final FedExLoggerInterface auditLogger = FedExLogger.getAuditLogger();
	private static final SimpleDateFormat auditDateFormat = new SimpleDateFormat("yyyyMMddhh24mmss");

	private boolean isInRole(String roleName, String uid) {
		try {
			logger.trace(new FedExLogEntry("isInRole evaluating: uid=" + uid + " roleName=" + roleName));
			Role role = RolesCacheFactory.getRolesCache().getRole(roleName);
			if (role != null) {
				if (role.equals(Role.ANYBODY)) {
					logger.trace(new FedExLogEntry("role is ANYBODY, returning true"));
					return true;
				}
				List<String> uids = role.getUids();
				List<String> groups = role.getGroups();
				if ((uids != null) && (uids.contains(uid))) {
					logger.trace(new FedExLogEntry("user is static member of role"));
					return true;
				}
				if (groups != null) {
					if (GroupsCacheFactory.getGroupsCache().memberOfAny(uid, groups)) {
						logger.trace(new FedExLogEntry("user is group member of role"));
						return true;
					}
				}
			}
			else {
				logger.trace(new FedExLogEntry("role not found in cache"));
			}
		}
		catch (SecurityConfigurationException sce) {
			logger.warn(new FedExLogEntry("Unable to retrieve rules. Check the security framework configuration.  Exception received is: "), sce);
		}
		logger.trace(new FedExLogEntry("user is not a member of role"));
		return false;
	}

	public Map<Permission, Boolean> isAllowed(String uid, Set<Permission> permissions, String roleName) {
		Map<Permission, Boolean> result = new HashMap();
		if (isInRole(roleName, uid)) {
			for (Permission p : permissions) {
				result.put(p, Boolean.valueOf(isAllowed(uid, p.getResource(), p.getAction())));
			}
		}
		return result;
	}

	public Map<Permission, Boolean> isAllowed(String uid, Set<Permission> permissions, Map context) {
		Map<Permission, Boolean> result = new HashMap();
		for (Permission p : permissions) {
			result.put(p, Boolean.valueOf(isAllowed(uid, p.getResource(), p.getAction(), context)));
		}
		return result;
	}

	public Map<String, Boolean> isAllowedForAllActions(String uid, Set<String> resources, Set<String> actions, Map context) {
		Map<String, Boolean> result = new HashMap();
		for (String resource : resources) {
			boolean allActionsAllowedForResource = true;
			for (String action : actions) {
				if (!isAllowed(uid, resource, action, context)) {
					allActionsAllowedForResource = false;
					break;
				}
			}
			result.put(resource, Boolean.valueOf(allActionsAllowedForResource));
		}
		return result;
	}

	public boolean isAllowed(String uid, String resource, String action) {
		return isAllowed(uid, resource, action, null);
	}

	public boolean isAllowed(String uid, String resource, String action, Map context) {
		try {
			logger.trace(new FedExLogEntry("isAllowed evaluating: uid=" + uid + " resource=" + resource + " action=" + action + " context=" + context));
			List<Rule> denyRules = RulesCacheFactory.getRulesCache().getDenyRules(resource, action, context);
			if (denyRules != null) {
				for (Rule rule : denyRules) {
					String roleName = rule.getRoleName();
					boolean isInRole = isInRole(roleName, uid);
					logger.trace(new FedExLogEntry(uid + " is in role " + roleName + "=" + isInRole));
					if (isInRole) {
						auditLogger.info(new FedExLogEntry(auditDateFormat.format(new Date()) + "|authz|" + uid + "|" + resource + "|" + action + "|false(deny)|" + rule));
						return false;
					}
				}
			}
			else {
				logger.trace(new FedExLogEntry("No Deny Rules Found for resource action"));
			}
			List<Rule> grantRules = RulesCacheFactory.getRulesCache().getGrantRules(resource, action, context);
			if (grantRules != null) {
				for (Rule rule : grantRules) {
					String roleName = rule.getRoleName();
					boolean isInRole = isInRole(roleName, uid);
					logger.debug(new FedExLogEntry(uid + " is in role " + roleName + "=" + isInRole));
					boolean passedCustom = true;
					CustomAuthorizor custom = rule.getCustomAuthorizor();
					if (custom != null) {
						passedCustom = custom.isAllowed(uid, resource, action, context);
						logger.trace(new FedExLogEntry(custom.getClass().getName() + " returned " + passedCustom));
					}
					if ((isInRole) && (passedCustom)) {
						auditLogger.info(new FedExLogEntry(auditDateFormat.format(new Date()) + "|authz|" + uid + "|" + resource + "|" + action + "|true|" + rule));
						return true;
					}
				}
			}
			else {
				logger.trace(new FedExLogEntry("No Grant Rules Found for resource action"));
			}
			if (IDM.idmCheck) {
				String delegator = IDM.evaluateIDMCache(uid, resource, action);
				if ((delegator != null) && (delegator.length() > 0) && (isAllowed(delegator, resource, action, null))) {
					auditLogger.info(new FedExLogEntry(auditDateFormat.format(new Date()) + "|authz|" + uid + "|" + resource + "|" + action + "|true|" + "IDMdelegator ID:".concat(delegator)));
					return true;
				}
				if ((delegator.length() > 0) && (!isAllowed(delegator, resource, action, null))) {
					auditLogger.info(new FedExLogEntry(auditDateFormat.format(new Date()) + "|authz|" + uid + "|" + resource + "|" + action + "|false|" + "IDMdelegator ID:".concat(delegator)));
					return false;
				}
			}
		}
		catch (SecurityConfigurationException sce) {
			logger.warn(new FedExLogEntry("Unable to retrieve rules. Check the security framework configuration.  Exception received is: "), sce);
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("An Exception was caught, returning false."), e);
			return false;
		}
		try {
			auditLogger.info(new FedExLogEntry(auditDateFormat.format(new Date()) + "|authz|" + uid + "|" + resource + "|" + action + "|false|"));
		}
		catch (Exception e) {
		}
		return false;
	}

	public boolean isAllowed(RestrictionData rstrData, String uid, String resource, String action)
			throws NullEntryListException {
		if (!isAllowed(uid, resource, action)) {
			logger.always(new FedExLogEntry("User is no allowed to." + action + " " + resource));
			return false;
		}
		if ((rstrData.getEmplId() != null) && (!rstrData.getEmplId().equalsIgnoreCase(uid))) {
			logger.always(new FedExLogEntry("User id is not same as the user id in restriction data"));
			return false;
		}
		RolesCacheEnterpriseImpl roles = RolesCacheEnterpriseImpl.getInstance();
		List<RestrictionDataItem> itemListFromCheck = null;
		if (rstrData != null) {
			itemListFromCheck = rstrData.getRestrictionList();
		}
		List<RestrictionDataItem> itemListFromCache = null;
		List<RestrictionData> rstrList = getRestrictionForUser(uid);
		if ((rstrList == null) || (rstrList.isEmpty())) {
			logger.always(new FedExLogEntry("No restrictions for this user in CDS"));
			return true;
		}
		List<String> rolesForUser = new ArrayList();
		List<Rule> grantRules = RulesCacheFactory.getRulesCache().getGrantRules(resource, action, null);
		if (grantRules != null) {
			for (Rule rule : grantRules) {
				String roleName = rule.getRoleName();
				if (isInRole(roleName, uid)) {
					rolesForUser.add(roleName);
				}
			}
		}
		boolean restrictionFound = false;
		for (Iterator i$ = rolesForUser.iterator(); i$.hasNext(); ) {
			String role = (String)i$.next();
			if (role == null) {
				throw new NullEntryListException("DJ said this would never happen.  He was wrong");
			}
			for (RestrictionData restrictionData : rstrList) {
				if (role.equalsIgnoreCase(restrictionData.getRoleNm())) {
					restrictionFound = true;
					itemListFromCache = restrictionData.getRestrictionList();
					if (itemListFromCache != null) {
						if ((itemListFromCheck != null) && (checkForRestrctionMatch(itemListFromCheck, itemListFromCache))) {
							logger.debug(new FedExLogEntry("check for restriction match is true..."));
							return true;
						}
						logger.debug(new FedExLogEntry("Restriction Item is null or the restriction does not match"));
					}
				}
				else {
					logger.trace(new FedExLogEntry("Role " + role + " does not equal role from cache: " + restrictionData.getRoleNm()));
				}
			}
		}
		return !restrictionFound;
	}

	protected boolean checkForRestrctionMatch(List<RestrictionDataItem> itemListFromUser, List<RestrictionDataItem> itemListFromCache)
			throws NullEntryListException {
		boolean isNull = false;
		for (Iterator i$ = itemListFromCache.iterator(); i$.hasNext(); ) {
			RestrictionDataItem item = (RestrictionDataItem)i$.next();
			for (RestrictionDataItem item1 : itemListFromUser) {
				if (item.getEntry() == null) {
					isNull = true;
					logger.always(new FedExLogEntry("Entry list in the cache is null,there should be at least one entry item. "));
				}
				else {
					isNull = false;
					if (compareEntryList(item1.getEntry(), item.getEntry())) {
						return true;
					}
					if (isNull) {
						throw new NullEntryListException();
					}
				}
			}
		}
		return false;
	}

	protected List<RestrictionData> getRestrictionForUser(String uid) {
		RestrictionCache rstrImpl = RestrictionCacheFactory.getRestrictionCache();
		ArrayList<RestrictionData> userRestrictionList = null;
		Set<String> roleNames = null;
		Map<String, RestrictionData> resListMap = rstrImpl.getRestrictions();
		if (resListMap != null) {
			roleNames = new HashSet(resListMap.keySet());
		}
		if (roleNames != null) {
			userRestrictionList = new ArrayList();
			Iterator<String> roleNamesIterator = roleNames.iterator();
			while (roleNamesIterator.hasNext()) {
				String roleName = roleNamesIterator.next();
				RestrictionData data = resListMap.get(roleName);
				if (data != null) {
					if ((data.getEmplId() != null) && (data.getEmplId().equalsIgnoreCase(uid))) {
						userRestrictionList.add(data);
					}
					else {
						if ((data.getGroupNm() != null) && (!data.getGroupNm().equals(""))) {
							List<String> groups = new ArrayList();
							groups.add(data.getGroupNm());
							if (GroupsCacheFactory.getGroupsCache().memberOfAny(uid, groups)) {
								userRestrictionList.add(data);
							}
						}
					}
				}
			}
		}
		return userRestrictionList;
	}

	protected boolean compareEntryList(List<Entry> entryFromUser, List<Entry> entryFromCache) {
		if ((entryFromUser == null) && (entryFromCache == null)) {
			return true;
		}
		if ((entryFromUser != null) && (entryFromCache == null)) {
			return false;
		}
		if ((entryFromUser == null) && (entryFromCache != null)) {
			return false;
		}
		if (entryFromUser.size() != entryFromCache.size()) {
			return false;
		}
		HashMap<String, String> map = new HashMap();
		for (Entry entry : entryFromUser) {
			if (entry == null) {
				return false;
			}
			if ((entry.getKey() != null) && (entry.getValue() != null)) {
				map.put(entry.getKey(), entry.getValue());
			}
			else {
				logger.always(new FedExLogEntry("Entry list has an entry with a null key/value. "));
			}
		}
		for (Entry entry : entryFromCache) {
			if (entry == null) {
				return false;
			}
			if ((entry.getKey() == null) || (entry.getValue() == null)) {
				logger.always(new FedExLogEntry("Entry list in the cache is null,there should be at least one entry item. "));
				return false;
			}
			if (!map.containsKey(entry.getKey())) {
				return false;
			}
			if (!map.get(entry.getKey()).equalsIgnoreCase(entry.getValue())) {
				String[] array = entry.getValue().split(",");
				String[] array2 = map.get(entry.getKey()).split(",");
				boolean found = false;
				for (String usrValue : array2) {
					for (String cacheVal : array) {
						if (cacheVal.equalsIgnoreCase(usrValue)) {
							found = true;
							break;
						}
					}
					if (found) {
						break;
					}
				}
				if (!found) {
					return false;
				}
			}
		}
		return true;
	}

	public static <T> boolean contains(String[] array, String v) {
		for (String e : array) {
			if ((v != null) && (v.equalsIgnoreCase(e))) {
				return true;
			}
		}
		return false;
	}

	public static void main(String[] args) {
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\server\AuthorizorEnterpriseImpl.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */