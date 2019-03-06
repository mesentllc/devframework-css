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
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.Timer;
import java.util.TimerTask;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;

public class GroupsCacheGroupMajorListImpl
		implements GroupsCache {
	private static final String DISK_CACHE_FILE = "GroupsCacheGroupMajorListImpl.cache";
	private static final FileLoader localLoader = new FileLoader();
	public static final String GROUPS_GRS_URL_PROP = "security.api.groups.grs.url";
	public static final String GROUPS_CACHE_REFRESH_IN_SECONDS_PROP = "security.api.groups.refresh";
	public static final String LOCAL_CACHE_DIR = "security.api.local.cache.dir";
	public static final String GRS_READ_TIMEOUT = "security.api.groups.grs.readtimeout";
	public static final String GRS_CONN_TIMEOUT = "security.api.groups.grs.conntimeout";
	private Map<String, List<String>> cache;
	private static Timer timer;
	private long refreshFrequency;
	private String grsUrl;
	private int grsReadTimeout;
	private int grsConnTimeout;
	private String localCacheDir;
	private Date lastRefreshDate;
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(GroupsCacheGroupMajorListImpl.class.getName());

	private GroupsCacheGroupMajorListImpl() {
		this("security.properties");
	}

	private GroupsCacheGroupMajorListImpl(String pathWithPropsFileName) {
		Properties props = FileLoader.getFileAsProperties(pathWithPropsFileName);
		if (props == null) {
			String msg = "Error attempting to set properties from property file. Check location and contents of property file at:  " + pathWithPropsFileName;
			logger.fatal(new FedExLogEntry(msg));
			throw new RuntimeException(msg);
		}
		if ((!props.containsKey("security.api.groups.grs.url")) || (!props.containsKey("security.api.groups.refresh")) || (!props.containsKey("security.api.local.cache.dir")) || (!props.containsKey("security.api.groups.grs.readtimeout")) || (!props.containsKey("security.api.groups.grs.conntimeout"))) {
			String msg = "Failed to configure groups cache. Path to the local cache directory may be missing or incorrect in the security.properties file.";
			logger.fatal(new FedExLogEntry("Failed to configure groups cache. Path to the local cache directory may be missing or incorrect in the security.properties file."));
			throw new RuntimeException("Failed to configure groups cache. Path to the local cache directory may be missing or incorrect in the security.properties file.");
		}
		this.grsUrl = props.getProperty("security.api.groups.grs.url");
		this.refreshFrequency = (1000L * Long.parseLong(props.getProperty("security.api.groups.refresh")));
		this.grsReadTimeout = (1000 * Integer.parseInt(props.getProperty("security.api.groups.grs.readtimeout")));
		this.grsConnTimeout = (1000 * Integer.parseInt(props.getProperty("security.api.groups.grs.conntimeout")));
		this.localCacheDir = props.getProperty("security.api.local.cache.dir");
		try {
			new File(this.localCacheDir).mkdirs();
		}
		catch (Exception e) {
			String msg = "Failed to configure enterprise groups cache  due to missing values provided for properties, exiting. Invalid property value in security.properties file.  Directory name: " + this.localCacheDir;
			logger.fatal(new FedExLogEntry(msg), e);
			throw new RuntimeException(msg, e);
		}
		this.cache = new ConcurrentHashMap();
		logger.info(new FedExLogEntry("Group cache initialized"));
	}

	private static final class GroupsCacheGroupMajorListImplHolder {
		private static GroupsCacheGroupMajorListImpl instance = null;

		public static GroupsCacheGroupMajorListImpl getInstance() {
			if (instance == null) {
				instance = new GroupsCacheGroupMajorListImpl(null);
			}
			return instance;
		}

		public static GroupsCacheGroupMajorListImpl getInstance(String propsFile) {
			if (instance == null) {
				instance = new GroupsCacheGroupMajorListImpl(propsFile);
			}
			return instance;
		}
	}

	public static final GroupsCacheGroupMajorListImpl getInstance() {
		logger.trace(new FedExLogEntry("GroupsCacheGroupMajorListImpl instance returned"));
		return GroupsCacheGroupMajorListImplHolder.getInstance();
	}

	public static final GroupsCacheGroupMajorListImpl getInstance(String propsFile) {
		logger.trace(new FedExLogEntry("GroupsCacheGroupMajorListImpl instance w/ props file returned"));
		return GroupsCacheGroupMajorListImplHolder.getInstance(propsFile);
	}

	private void startTimer() {
		if (timer != null) {
			timer.cancel();
		}
		timer = null;
		timer = new Timer(true);
		timer.schedule(new CacheRefreshTask(), this.refreshFrequency, this.refreshFrequency);
	}

	private Set<String> getCachedGroups() {
		if (this.cache.size() > 0) {
			return this.cache.keySet();
		}
		return null;
	}

	private void refreshGroups() {
		if (this.cache.size() > 0) {
			cacheMembersOf(this.cache.keySet(), false);
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
		if (this.cache.size() > 0) {
			if ((groupNames != null) && (groupNames.size() > 0)) {
				for (String groupName : groupNames) {
					if ((groupName != null) && (!"".equals(groupName.trim()))) {
						if ((this.cache.get(groupName) != null) && (this.cache.get(groupName).contains(uid))) {
							inGroup = true;
							break;
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
		try {
			URL url = new URL(this.grsUrl);
			for (String groupName : groupNames) {
				if ((groupName != null) && (!"".equals(groupName.trim()))) {
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
							String[] uidArray = new String[st.countTokens()];
							int i = 0;
							while (st.hasMoreTokens()) {
								uidArray[(i++)] = st.nextToken().intern();
							}
							uids = null;
							st = null;
							this.cache.put(groupName.intern(), Arrays.asList(uidArray));
							uidArray = null;
						}
						else {
							logger.warn(new FedExLogEntry("GRS did not return ay results querying for membersOf=" + groupName + ", LKG not updated"));
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
			logger.warn(new FedExLogEntry("Error refreshing group cache from GRS: " + e.getMessage()));
		}
		finally {
			try {
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
			if (useLKG) {
				Set<String> uncachedGroups = new HashSet(groupNames);
				Set<String> cachedGroups = this.cache.keySet();
				if (this.cache.keySet() != null) {
					uncachedGroups.removeAll(cachedGroups);
				}
				if (uncachedGroups.size() > 0) {
					Object fromDisk = localLoader.readObjectFromDisk(this.localCacheDir + File.separator + "GroupsCacheGroupMajorListImpl.cache");
					if ((fromDisk != null) && ((fromDisk instanceof Map))) {
						try {
							Map<String, List<String>> cacheFromDisk = (Map)fromDisk;
							if ((cacheFromDisk != null) && (cacheFromDisk.size() > 0)) {
								cacheFromDisk.keySet().retainAll(uncachedGroups);
								this.cache.putAll(cacheFromDisk);
							}
							cacheFromDisk = null;
						}
						catch (ClassCastException cce) {
							logger.warn(new FedExLogEntry("Error attempting to use last known good as a source for group membership. Exception received is: "), cce);
						}
					}
					fromDisk = null;
				}
			}
		}
		if (timer == null) {
			startTimer();
		}
		if (this.lastRefreshDate == null) {
			this.lastRefreshDate = new Date();
		}
		try {
			localLoader.saveObjectToDisk(this.localCacheDir + File.separator + "GroupsCacheGroupMajorListImpl.cache", this.cache);
		}
		catch (Exception e) {
			logger.always(new FedExLogEntry("[GroupsCache]Error attempting to write LKG for policy to disk: " + this.localCacheDir + File.separator + "GroupsCacheGroupMajorListImpl.cache"), e);
		}
	}

	public List<String> getMembersOfGroup(String groupName) {
		HttpURLConnection conn = null;
		DataOutputStream dos = null;
		BufferedReader in = null;
		List<String> members = new ArrayList();
		try {
			URL url = new URL(this.grsUrl);
			if ((groupName != null) && (!"".equals(groupName.trim()))) {
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
						TreeSet<String> uidSet = new TreeSet();
						while (st.hasMoreTokens()) {
							uidSet.add(st.nextToken().intern());
						}
						uids = null;
						st = null;
						members.addAll(uidSet);
						uidSet.clear();
						uidSet = null;
					}
					else {
						logger.warn(new FedExLogEntry("unexpected result from GRS for membersOf=" + groupName + ", unable to complete."));
					}
				}
				in.close();
				in = null;
				conn.disconnect();
				conn = null;
			}
			return members;
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Error refreshing group cache from GRS: " + e.getMessage()));
		}
		finally {
			try {
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
		}
		return members;
	}

	public List<String> getMembersOfGroupCached(String groupName) {
		List<String> members = this.cache.get(groupName);
		if ((members != null) && (members.size() == 0)) {
			members = null;
		}
		return members;
	}

	public List<String> getGroupsForUser(String userId) {
		HttpURLConnection conn = null;
		DataOutputStream dos = null;
		BufferedReader in = null;
		ArrayList<String> groups = new ArrayList();
		try {
			URL url = new URL(this.grsUrl);
			if ((userId != null) && (!"".equals(userId.trim()))) {
				conn = (HttpURLConnection)url.openConnection();
				conn.setDoInput(true);
				conn.setDoOutput(true);
				conn.setUseCaches(false);
				conn.setRequestMethod("POST");
				conn.setRequestProperty("Connection", "Keep-Alive");
				conn.setReadTimeout(this.grsReadTimeout);
				conn.setConnectTimeout(this.grsConnTimeout);
				dos = new DataOutputStream(conn.getOutputStream());
				dos.writeBytes("uid=" + URLEncoder.encode(userId, "UTF-8"));
				dos.flush();
				dos.close();
				dos = null;
				in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
				String str;
				if ((str = in.readLine()) != null) {
					StringTokenizer st = new StringTokenizer(str, ":");
					String[] uidArray = new String[st.countTokens()];
					int i = 0;
					while (st.hasMoreTokens()) {
						uidArray[(i++)] = st.nextToken().intern();
					}
					str = null;
					st = null;
					groups.addAll(Arrays.asList(uidArray));
					uidArray = null;
				}
				in.close();
				in = null;
				conn.disconnect();
				conn = null;
			}
			try {
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
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Error retrieving group membership from GRS: " + e.getMessage()));
		}
		finally {
			try {
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
		}
		groups = null;
		label623:
		return groups;
	}

	public List<String> getGroupsForUserCached(String userId) {
		ArrayList<String> groups = new ArrayList();
		for (String key : this.cache.keySet()) {
			if (this.cache.get(key).contains(userId)) {
				groups.add(key);
			}
		}
		if (groups.size() == 0) {
			groups = null;
		}
		return groups;
	}

	public List<String> getGroupListFromPolicy() {
		ArrayList<String> groupList = new ArrayList();
		if (this.cache != null) {
			groupList.addAll(this.cache.keySet());
		}
		else {
			groupList = null;
		}
		return groupList;
	}

	private class CacheRefreshTask
			extends TimerTask {
		private CacheRefreshTask() {
		}

		public void run() {
			GroupsCacheGroupMajorListImpl.getInstance().refreshGroups();
		}
	}

	public static void cancelTimerTask() {
		if (timer != null) {
			timer.cancel();
		}
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\server\GroupsCacheGroupMajorListImpl.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */