package com.fedex.security.server;

import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import com.fedex.security.common.FileLoader;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;

public class GroupsCachePersonMajorListImpl
		implements GroupsCache {
	private static final String DISK_CACHE_FILE = "GroupsCachePersonMajorListImpl.cache";
	private static final FileLoader localLoader = new FileLoader();
	public static final String GROUPS_GRS_URL_PROP = "security.api.groups.grs.url";
	public static final String GROUPS_CACHE_REFRESH_IN_SECONDS_PROP = "security.api.groups.refresh";
	public static final String LOCAL_CACHE_DIR = "security.api.local.cache.dir";
	public static final String GRS_READ_TIMEOUT = "security.api.groups.grs.readtimeout";
	public static final String GRS_CONN_TIMEOUT = "security.api.groups.grs.conntimeout";
	private Map<String, List<String>> cache;
	private Timer timer;
	private long refreshFrequency;
	private String grsUrl;
	private int grsReadTimeout;
	private int grsConnTimeout;
	private String localCacheDir;
	private Date lastRefreshDate;
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(GroupsCachePersonMajorListImpl.class.getName());

	private GroupsCachePersonMajorListImpl() {
		this("security.properties");
	}

	private GroupsCachePersonMajorListImpl(String pathWithPropsFileName) {
		Properties props = FileLoader.getFileAsProperties(pathWithPropsFileName);
		if (props == null) {
			String msg = "Unable to locate " + pathWithPropsFileName;
			logger.fatal(new FedExLogEntry(msg));
			throw new RuntimeException(msg);
		}
		if ((!props.containsKey("security.api.groups.grs.url")) || (!props.containsKey("security.api.groups.refresh")) || (!props.containsKey("security.api.local.cache.dir")) || (!props.containsKey("security.api.groups.grs.readtimeout")) || (!props.containsKey("security.api.groups.grs.conntimeout"))) {
			String msg = "Failed to configure groups cache, exiting. Verify content of security properties";
			logger.fatal(new FedExLogEntry("Failed to configure groups cache, exiting. Verify content of security properties"));
			throw new RuntimeException("Failed to configure groups cache, exiting. Verify content of security properties");
		}
		this.grsUrl = props.getProperty("security.api.groups.grs.url");
		this.refreshFrequency = (1000L * Long.parseLong(props.getProperty("security.api.groups.refresh")));
		this.grsReadTimeout = (1000 * Integer.parseInt(props.getProperty("security.api.groups.grs.readtimeout")));
		this.grsConnTimeout = (1000 * Integer.parseInt(props.getProperty("security.api.groups.grs.conntimeout")));
		this.localCacheDir = props.getProperty("security.api.local.cache.dir");
		new File(this.localCacheDir).mkdirs();
		this.cache = new ConcurrentHashMap();
		logger.info(new FedExLogEntry("Group cache initialized"));
	}

	private static final class GroupsCachePersonMajorListImplHolder {
		private static GroupsCachePersonMajorListImpl instance = null;

		public static GroupsCachePersonMajorListImpl getInstance() {
			if (instance == null) {
				instance = new GroupsCachePersonMajorListImpl(null);
			}
			return instance;
		}

		public static GroupsCachePersonMajorListImpl getInstance(String propsFile) {
			if (instance == null) {
				instance = new GroupsCachePersonMajorListImpl(propsFile);
			}
			return instance;
		}
	}

	public static final GroupsCachePersonMajorListImpl getInstance() {
		logger.trace(new FedExLogEntry("GroupsCachePersonMajorListImpl instance returned"));
		return GroupsCachePersonMajorListImplHolder.getInstance();
	}

	public static final GroupsCachePersonMajorListImpl getInstance(String propsFile) {
		logger.trace(new FedExLogEntry("GroupsCachePersonMajorListImpl instance w/ props file returned"));
		return GroupsCachePersonMajorListImplHolder.getInstance(propsFile);
	}

	private void startTimer() {
		if (this.timer != null) {
			this.timer.cancel();
		}
		this.timer = null;
		this.timer = new Timer(true);
		this.timer.schedule(new CacheRefreshTask(), this.refreshFrequency, this.refreshFrequency);
	}

	private Set<String> getCachedGroups() {
		if (this.cache.size() > 0) {
			Set<String> cachedGroups = new HashSet();
			List<List<String>> allGroups = new ArrayList(this.cache.values());
			for (List<String> groups : allGroups) {
				cachedGroups.addAll(groups);
			}
			return cachedGroups;
		}
		return null;
	}

	private void refreshGroups() {
		if (this.cache.size() > 0) {
			cacheMembersOf(getCachedGroups(), false);
			logger.trace(new FedExLogEntry("group refresh complete"));
		}
		this.lastRefreshDate = new Date();
	}

	public boolean memberOf(String uid, String groupName) {
		List<String> groups = new ArrayList(1);
		groups.add(groupName);
		return memberOfAny(uid, groups);
	}

	public boolean memberOfAny(String uid, List<String> groupNames) {
		if ((this.cache.size() > 0) && (System.currentTimeMillis() - this.lastRefreshDate.getTime() > 1.5D * this.refreshFrequency)) {
			startTimer();
		}
		boolean inGroup = false;
		List<String> groups;
		if (this.cache.size() > 0) {
			if ((groupNames != null) && (groupNames.size() > 0)) {
				groups = this.cache.get(uid);
				if (groups != null) {
					for (String groupName : groupNames) {
						if ((groupName != null) && (!"".equals(groupName.trim()))) {
							if (groups.contains(groupName)) {
								inGroup = true;
								break;
							}
						}
					}
				}
			}
		}
		return inGroup;
	}

	public void cache(Set<Role> roles) {
		Set<String> newGroups = null;
		if (roles != null) {
			newGroups = new HashSet();
			for (Role r : roles) {
				if (r != null) {
					List<String> groups = r.getGroups();
					if (groups != null) {
						newGroups.addAll(groups);
					}
				}
			}
		}
		if ((newGroups != null) && (newGroups.size() > 0)) {
			Set<String> cachedGroups = getCachedGroups();
			if (cachedGroups != null) {
				newGroups.removeAll(cachedGroups);
			}
			if (newGroups.size() > 0) {
				cacheMembersOf(newGroups, true);
			}
		}
	}

	private void cacheMembersOf(Set<String> groupNames, boolean useLKG) {
		HttpURLConnection conn = null;
		DataOutputStream dos = null;
		BufferedReader in = null;
		boolean grsFailed = false;
		try {
			URL url = new URL(this.grsUrl);
			for (String groupName : groupNames) {
				if ((groupName != null) && (!"".equals(groupName.trim()))) {
					groupName = groupName.intern();
					conn = (HttpURLConnection)url.openConnection();
					conn.setDoInput(true);
					conn.setDoOutput(true);
					conn.setUseCaches(false);
					conn.setRequestMethod("POST");
					conn.setRequestProperty("Connection", "Keep-Alive");
					conn.setReadTimeout(this.grsReadTimeout);
					conn.setConnectTimeout(this.grsConnTimeout);
					dos = new DataOutputStream(conn.getOutputStream());
					dos.writeBytes("membersOf=" + URLEncoder.encode(groupName, "UTF-8"));
					dos.flush();
					dos.close();
					dos = null;
					in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
					String str;
					if ((str = in.readLine()) != null) {
						if (str.startsWith(groupName + ",")) {
							String uids = str.substring(str.indexOf(",") + 1);
							str = null;
							StringTokenizer st = new StringTokenizer(uids, ":");
							Set<String> uidSet = new HashSet(st.countTokens());
							int i = 0;
							while (st.hasMoreTokens()) {
								uidSet.add(st.nextToken().intern());
							}
							uids = null;
							st = null;
							for (String uid : uidSet) {
								List<String> groups = this.cache.get(uid);
								if (groups == null) {
									groups = new ArrayList();
								}
								if (!groups.contains(groupName)) {
									groups.add(groupName);
									this.cache.put(uid, groups);
								}
							}
							for (String uid : this.cache.keySet()) {
								List<String> groups = this.cache.get(uid);
								if ((groups != null) && (!uidSet.contains(uid))) {
									groups.remove(groupName);
								}
							}
							uidSet = null;
						}
						else {
							logger.warn(new FedExLogEntry("unexpected result from GRS for membersOf=" + groupName + ", skipping cache update"));
						}
					}
					in.close();
					in = null;
					conn.disconnect();
					conn = null;
				}
			}
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Error refreshing group cache from GRS"), e);
			grsFailed = true;
		}
		finally {
			try {
				Object fromDisk;
				Map<String, List<String>> cacheFromDisk;
				if (dos != null) {
					dos.close();
				}
			}
			catch (Exception e) {
				logger.warn(new FedExLogEntry("Error closing data output stream"), e);
			}
			try {
				if (in != null) {
					in.close();
				}
			}
			catch (Exception e) {
				logger.warn(new FedExLogEntry("Error closing input stream"), e);
			}
			try {
				if (conn != null) {
					conn.disconnect();
				}
			}
			catch (Exception e) {
				logger.warn(new FedExLogEntry("Error closing URLConnection"), e);
			}
			if ((grsFailed) && (useLKG)) {
				Object fromDisk = localLoader.readObjectFromDisk(this.localCacheDir + File.separator + "GroupsCachePersonMajorListImpl.cache");
				if ((fromDisk != null) && ((fromDisk instanceof Map))) {
					try {
						Map<String, List<String>> cacheFromDisk = (Map)fromDisk;
						if ((cacheFromDisk != null) && (cacheFromDisk.size() > 0)) {
							this.cache.putAll(cacheFromDisk);
						}
						cacheFromDisk = null;
					}
					catch (ClassCastException cce) {
						logger.warn(new FedExLogEntry("Error casting cache from disk"), cce);
					}
				}
				fromDisk = null;
			}
		}
		if (this.timer == null) {
			startTimer();
		}
		if (this.lastRefreshDate == null) {
			this.lastRefreshDate = new Date();
		}
		localLoader.saveObjectToDisk(this.localCacheDir + File.separator + "GroupsCachePersonMajorListImpl.cache", this.cache);
	}

	private class CacheRefreshTask
			extends TimerTask {
		private CacheRefreshTask() {
		}

		public void run() {
			GroupsCachePersonMajorListImpl.getInstance().refreshGroups();
		}
	}

	public List<String> getMembersOfGroup(String groupName) {
		return null;
	}

	public List<String> getGroupsForUser(String userId) {
		return null;
	}

	public List<String> getGroupsForUserCached(String userId) {
		return null;
	}

	public List<String> getMembersOfGroupCached(String groupName) {
		return null;
	}

	public List<String> getGroupListFromPolicy() {
		return null;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\server\GroupsCachePersonMajorListImpl.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */