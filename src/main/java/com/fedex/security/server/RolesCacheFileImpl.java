package com.fedex.security.server;

import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import com.fedex.security.common.FileLoader;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Pattern;

public class RolesCacheFileImpl
		implements RolesCache {
	private static final String DEFAULT_FILE = "authorization.roles";
	private Map<String, Role> cache;
	private String rolesFileName;
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(RolesCacheFileImpl.class.getName());

	private RolesCacheFileImpl() {
		this.cache = new HashMap();
		logger.info(new FedExLogEntry("Roles cache initialized"));
	}

	private static final class RolesCacheFileImplHolder {
		private static final RolesCacheFileImpl instance = new RolesCacheFileImpl();
	}

	public static final RolesCacheFileImpl getInstance() {
		return RolesCacheFileImplHolder.instance;
	}

	public final synchronized void configure() {
		configure(null);
	}

	public final synchronized void configure(String rolesFileName) {
		if (this.cache.size() == 0) {
			if (rolesFileName != null) {
				this.rolesFileName = rolesFileName;
				logger.info(new FedExLogEntry("Using Roles File:" + this.rolesFileName));
			}
			else {
				this.rolesFileName = "authorization.roles";
				logger.info(new FedExLogEntry("rolesFileName is null, using filename of " + this.rolesFileName));
			}
			load();
		}
		else {
			logger.info(new FedExLogEntry("Roles have already been loaded.  Roles can only be loaded once, ignoring"));
		}
	}

	public Role getRole(String roleName) {
		Role role = null;
		if ("*".equals(roleName)) {
			role = Role.ANYBODY;
		}
		else {
			if ((this.cache.size() > 0) && (roleName != null)) {
				role = this.cache.get(roleName);
			}
			else {
				logger.warn(new FedExLogEntry("Unable to find role in cache for roleName=" + roleName + ", cache size=" + this.cache.size()));
			}
		}
		return role;
	}

	public Set<Role> getRoles() {
		if (this.cache.size() > 0) {
			return new HashSet(this.cache.values());
		}
		return null;
	}

	public Set<String> getRoleNames() {
		if (this.cache.size() > 0) {
			return new HashSet(this.cache.keySet());
		}
		return null;
	}

	private synchronized void load() {
		if (this.rolesFileName != null) {
			Properties roleDefs = FileLoader.getFileAsProperties(this.rolesFileName);
			Pattern roleNameWhiteList;
			Pattern roleDefWhiteList;
			Enumeration e;
			if (roleDefs != null) {
				roleNameWhiteList = Pattern.compile("[a-zA-Z0-9_-]+");
				roleDefWhiteList = Pattern.compile("[^,:\\s]+(,[^,:\\s]+)*:|:[^,:\\s]+(,[^,:\\s]+)*|[^,:\\s]+(,[^,:\\s]+)*:[^,:\\s]+(,[^,:\\s]+)*");
				for (e = roleDefs.propertyNames(); e.hasMoreElements(); ) {
					String roleName = (String)e.nextElement();
					String roleDef = roleDefs.getProperty(roleName).trim();
					logger.trace(new FedExLogEntry("reading roleName=" + roleName + " roleDef=" + roleDef));
					if ((roleName != null) && (roleNameWhiteList.matcher(roleName).matches()) && (roleDef != null) && (roleDefWhiteList.matcher(roleDef).matches())) {
						String[] roleDefArray = roleDef.split(":", 3);
						if ((roleDefArray != null) && (roleDefArray.length == 2)) {
							List<String> groups = null;
							List<String> uids = null;
							if (roleDefArray[0].length() > 0) {
								groups = Arrays.asList(roleDefArray[0].split(","));
							}
							if (roleDefArray[1].length() > 0) {
								uids = Arrays.asList(roleDefArray[1].split(","));
							}
							Role role = new Role(groups, uids);
							this.cache.put(roleName, role);
						}
						else {
							logger.fatal(new FedExLogEntry("bad role: need one colon for " + roleName));
							throw new RuntimeException("Unable to parse roles.");
						}
					}
					else {
						logger.fatal(new FedExLogEntry("bad role: " + roleName));
						throw new RuntimeException("Unable to parse roles.");
					}
				}
			}
			else {
				logger.fatal(new FedExLogEntry("Unable to load roles file: " + this.rolesFileName));
				throw new RuntimeException("Unable to load roles.");
			}
		}
		logger.trace(new FedExLogEntry("Roles=" + this.cache));
	}

	public void triggerUpdate() {
	}

	public List<String> getRolesForUser(String uid) {
		return getRolesForUser(uid, true);
	}

	public List<String> getRolesForUser(String uid, boolean groupAssignedRole) {
		Set<String> userRoles = new HashSet();
		Set<String> roleNames = RolesCacheFactory.getRolesCache().getRoleNames();
		Iterator<String> roleNamesIterator = roleNames.iterator();
		while (roleNamesIterator.hasNext()) {
			String roleName = roleNamesIterator.next();
			Role role = RolesCacheFactory.getRolesCache().getRole(roleName);
			if (role != null) {
				boolean isStaticMember = false;
				List<String> uids = role.getUids();
				List<String> groups = role.getGroups();
				if ((uids != null) && (uids.contains(uid))) {
					logger.trace(new FedExLogEntry(uid + " user is static member of role " + roleName));
					userRoles.add(roleName);
					isStaticMember = true;
				}
				if ((groupAssignedRole) && (groups != null) && (!isStaticMember)) {
					if (GroupsCacheFactory.getGroupsCache().memberOfAny(uid, groups)) {
						logger.trace(new FedExLogEntry(uid + " user is group member of role " + roleName));
						userRoles.add(roleName);
					}
				}
			}
		}
		return new ArrayList(userRoles);
	}

	public List<String> getGroupsForRole(String roleName) {
		Role role = RolesCacheFactory.getRolesCache().getRole(roleName);
		if (role != null) {
			return role.getGroups();
		}
		return null;
	}
}
