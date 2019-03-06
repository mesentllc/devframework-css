package com.fedex.security.server;

import com.fedex.enterprise.security.role.restriction.RestrictionData;
import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import com.fedex.security.exceptions.SecurityConfigurationException;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class AuthorizorImpl
		implements Authorizor {
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(AuthorizorImpl.class.getName());
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
			List<Rule> rules = RulesCacheFactory.getRulesCache().getRules(resource, action);
			if (rules != null) {
				for (Rule rule : rules) {
					String roleName = rule.getRoleName();
					boolean isInRole = isInRole(roleName, uid);
					logger.trace(new FedExLogEntry(uid + " is in role " + roleName + "=" + isInRole));
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
				logger.trace(new FedExLogEntry("No Rules Found for resource action"));
			}
		}
		catch (SecurityConfigurationException sce) {
			logger.warn(new FedExLogEntry("Unable to retrieve rules. Check the security framework configuration.  Exception received is: "), sce);
		}
		auditLogger.info(new FedExLogEntry(auditDateFormat.format(new Date()) + "|authz|" + uid + "|" + resource + "|" + action + "|false|"));
		return false;
	}

	public boolean isAllowed(RestrictionData resData, String uid, String resource, String action) {
		return false;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\server\AuthorizorImpl.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */