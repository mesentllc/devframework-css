package com.fedex.security.server;

import com.fedex.enterprise.security.api.SecurityService;
import com.fedex.enterprise.security.api.SecurityServiceImpl;
import com.fedex.enterprise.security.role.AppRoleData;
import com.fedex.enterprise.security.role.GroupRoleData;
import com.fedex.enterprise.security.role.RoleData;
import com.fedex.enterprise.security.role.UserRoleData;
import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import com.fedex.framework.utility.FedExAppFrameworkProperties;
import com.fedex.security.common.FileLoader;
import com.fedex.security.exceptions.SecurityConfigurationException;

import java.io.File;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class RolesCacheEnterpriseImpl
		implements RolesCache {
	private static final String DISK_CACHE_FILE = "RolesCacheEnterpriseImpl.cache";
	public static final String POLICY_REFRESH_IN_SECONDS_PROP = "security.api.service.cache";
	public static final String LOCAL_CACHE_DIR = "security.api.local.cache.dir";
	private final String appId = getClientIdFromFingerPrint();
	private static final FileLoader localLoader = new FileLoader();
	private Map<String, Role> cache;
	private String localCacheDir;
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(RolesCacheEnterpriseImpl.class.getName());

	private RolesCacheEnterpriseImpl() {
		this("security.properties");
	}

	private RolesCacheEnterpriseImpl(String pathWithPropsFileName) {
		Properties props = FileLoader.getFileAsProperties(pathWithPropsFileName);
		if (!props.containsKey("security.api.local.cache.dir")) {
			String msg = "Failed to configure enterprise roles cache due to missing values provided for properties, exiting. Missing or invalid property in security.properties file.";
			logger.fatal(new FedExLogEntry("Failed to configure enterprise roles cache due to missing values provided for properties, exiting. Missing or invalid property in security.properties file."));
			throw new RuntimeException("Failed to configure enterprise roles cache due to missing values provided for properties, exiting. Missing or invalid property in security.properties file.");
		}
		try {
			this.localCacheDir = props.getProperty("security.api.local.cache.dir");
			new File(this.localCacheDir).mkdirs();
		}
		catch (Exception e) {
			String msg = "Failed to configure enterprise roles cache due to invalid values provided for properties, exiting. Missing or invalid property in security.properties file.  Directory is: security.api.local.cache.dir";
			logger.fatal(new FedExLogEntry("Failed to configure enterprise roles cache due to invalid values provided for properties, exiting. Missing or invalid property in security.properties file.  Directory is: security.api.local.cache.dir"));
			throw new RuntimeException("Failed to configure enterprise roles cache due to invalid values provided for properties, exiting. Missing or invalid property in security.properties file.  Directory is: security.api.local.cache.dir", e);
		}
		this.cache = new ConcurrentHashMap();
		load();
		logger.info(new FedExLogEntry("Roles cache initialized"));
	}

	private static final class RolesCacheEnterpriseImplHolder {
		private static RolesCacheEnterpriseImpl instance = null;

		public static RolesCacheEnterpriseImpl getInstance() {
			if (instance == null) {
				instance = new RolesCacheEnterpriseImpl(null);
			}
			return instance;
		}

		public static RolesCacheEnterpriseImpl getInstance(String propsFile) {
			if (instance == null) {
				instance = new RolesCacheEnterpriseImpl(propsFile);
			}
			return instance;
		}
	}

	public static final RolesCacheEnterpriseImpl getInstance() {
		logger.trace(new FedExLogEntry("RolesCacheEnterpriseImpl instance returned"));
		return RolesCacheEnterpriseImplHolder.getInstance();
	}

	public static final RolesCacheEnterpriseImpl getInstance(String propsFile) {
		logger.trace(new FedExLogEntry("RolesCacheEnterpriseImpl instance w/ props file returned"));
		return RolesCacheEnterpriseImplHolder.getInstance(propsFile);
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

	public synchronized void load() {
		SecurityService secService = new SecurityServiceImpl();
		List<RoleData> roles = null;
		List<Long> roleDocIds = new ArrayList();
		roleDocIds = RulesCacheFactory.getRulesCache().getRoleDocIds();
		if ((roleDocIds != null) && (roleDocIds.size() > 0)) {
			logger.debug(new FedExLogEntry("[Load Roles]Number of Roles from Rules = " + roleDocIds.size()));
			roles = secService.getAllRolesForApplicationAPI(roleDocIds, this.appId);
		}
		else {
			logger.warn(new FedExLogEntry("Could not load Rules containing roles due to these possible causes: Rules cache was not initialized, or Rules cache did not complete update."));
		}
		if ((roles == null) || (roles.isEmpty())) {
			logger.warn(new FedExLogEntry("[Load Roles]Failed to retrieve Roles from CDS, attempting to fall back to LKG..."));
			Object fromDisk = localLoader.readObjectFromDisk(this.localCacheDir + File.separator + "RolesCacheEnterpriseImpl.cache");
			if ((fromDisk != null) && ((fromDisk instanceof Map))) {
				try {
					Map<String, Role> roleCacheFromDisk = (Map)fromDisk;
					if ((roleCacheFromDisk != null) && (!roleCacheFromDisk.isEmpty())) {
						this.cache.putAll(roleCacheFromDisk);
						logger.warn(new FedExLogEntry("[Load Roles]Successfully loaded Role LKG from disk."));
					}
				}
				catch (Exception e) {
					logger.error(new FedExLogEntry("Error attempting to load roles from LKG. Exception received was: "), e);
				}
			}
			fromDisk = null;
		}
		else {
			logger.debug(new FedExLogEntry("[Load Roles]Total number of roles returned from CDS: " + roles.size()));
			for (RoleData roleData : roles) {
				logger.trace(new FedExLogEntry("App/Role: " + roleData.getAppId() + "/" + roleData.getRoleNm()));
				logger.trace(new FedExLogEntry("Humans: " + roleData.getUserMemberList()));
				logger.trace(new FedExLogEntry("Applications: " + roleData.getAppMemberList()));
				logger.trace(new FedExLogEntry("Groups: " + roleData.getGroupMemberList()));
				List<String> uids = new ArrayList();
				List<String> groups = new ArrayList();
				for (UserRoleData userRole : roleData.getUserMemberList()) {
					uids.add(userRole.getEmpNbr());
				}
				for (AppRoleData appRole : roleData.getAppMemberList()) {
					uids.add("APP" + appRole.getAppId());
				}
				for (GroupRoleData groupRole : roleData.getGroupMemberList()) {
					groups.add(groupRole.getGroupNm());
				}
				Role role = new Role(groups, uids);
				logger.debug(new FedExLogEntry("Adding Role " + roleData.getRoleNm() + ": " + role.toString()));
				this.cache.put(roleData.getRoleNm(), role);
			}
			try {
				localLoader.saveObjectToDisk(this.localCacheDir + File.separator + "RolesCacheEnterpriseImpl.cache", this.cache);
				logger.debug(new FedExLogEntry("[RolesCache]LKG is written to disk at location: " + this.localCacheDir + "RolesCacheEnterpriseImpl.cache"));
			}
			catch (Exception e) {
				logger.warn(new FedExLogEntry("[RolesCache]Error attempting to write LKG for policy to disk: " + this.localCacheDir + File.separator + "RolesCacheEnterpriseImpl.cache"), e);
			}
		}
	}

	private static final String getClientIdFromFingerPrint() {
		String clientId = FedExAppFrameworkProperties.getInstance().getAppId();
		if ((clientId == null) || (clientId.trim().equals(""))) {
			clientId = "BAD";
		}
		if (clientId.matches("^APP[0-9]*[1-9][0-9]*$")) {
			return clientId.substring(3);
		}
		if (clientId.matches("^[0-9]*[1-9][0-9]*$")) {
			return clientId;
		}
		logger.fatal(new FedExLogEntry("Application ID is missing or invalid. Verify location and appID contents in fp.properties file. Can not retrieve security policy."));
		throw new SecurityConfigurationException("Unable to determine application id (check app.id), unable to retrieve security policy!");
	}

	public void triggerUpdate() {
		load();
		GroupsCacheGroupMajorListImpl groupsCache = GroupsCacheGroupMajorListImpl.getInstance();
		groupsCache.cache(RolesCacheFactory.getRolesCache().getRoles());
	}

	public List<String> getGroupsForRole(String roleName) {
		Role role = RolesCacheFactory.getRolesCache().getRole(roleName);
		if (role != null) {
			return role.getGroups();
		}
		return null;
	}

	public List<String> getMembersForRole(String roleName) {
		Role role = RolesCacheFactory.getRolesCache().getRole(roleName);
		List<String> memberList = new ArrayList();
		if (role != null) {
			memberList = role.getUids();
			List<String> groups = role.getGroups();
			if (groups != null) {
				for (String group : groups) {
					List<String> members = GroupsCacheFactory.getGroupsCache().getMembersOfGroup(group);
					if (members != null) {
						for (String uid : members) {
							memberList.add(uid);
						}
					}
				}
			}
		}
		else {
			return null;
		}
		return memberList;
	}
}
