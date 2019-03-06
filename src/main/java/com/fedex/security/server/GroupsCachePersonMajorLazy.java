package com.fedex.security.server;

import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import com.fedex.security.common.FileLoader;
import com.fedex.security.common.GRSErrorCodes;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;

public class GroupsCachePersonMajorLazy
		implements GroupsCache {
	private static final String GROUPS_GRS_URL_PROP = "security.api.groups.grs.url";
	private static final String GROUPS_CACHE_REFRESH_IN_SECONDS_PROP = "security.api.groups.refresh";
	public static final String GRS_READ_TIMEOUT = "security.api.groups.grs.readtimeout";
	public static final String GRS_CONN_TIMEOUT = "security.api.groups.grs.conntimeout";
	private Map<String, String> cache;
	private Timer timer;
	private long refreshFrequency;
	private String grsUrl;
	private int grsReadTimeout;
	private int grsConnTimeout;
	private Date lastRefreshDate;
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(GroupsCachePersonMajorLazy.class.getName());

	private GroupsCachePersonMajorLazy() {
		this("security.properties");
	}

	private GroupsCachePersonMajorLazy(String pathWithPropsFileName) {
		Properties props = FileLoader.getFileAsProperties(pathWithPropsFileName);
		if (props == null) {
			String msg = "Error attempting to set properties from property file. Check location and contents of property file at: " + pathWithPropsFileName;
			logger.fatal(new FedExLogEntry(msg));
			throw new RuntimeException(msg);
		}
		if ((!props.containsKey("security.api.groups.grs.url")) || (!props.containsKey("security.api.groups.refresh")) || (!props.containsKey("security.api.groups.grs.readtimeout")) || (!props.containsKey("security.api.groups.grs.conntimeout"))) {
			String msg = "Failed to configure groups cache. Path to the local cache directory may be missing or incorrect in the security.properties file.";
			logger.fatal(new FedExLogEntry("Failed to configure groups cache. Path to the local cache directory may be missing or incorrect in the security.properties file."));
			throw new RuntimeException("Failed to configure groups cache. Path to the local cache directory may be missing or incorrect in the security.properties file.");
		}
		this.grsUrl = props.getProperty("security.api.groups.grs.url");
		this.refreshFrequency = (1000L * Long.parseLong(props.getProperty("security.api.groups.refresh")));
		this.grsReadTimeout = (1000 * Integer.parseInt(props.getProperty("security.api.groups.grs.readtimeout")));
		this.grsConnTimeout = (1000 * Integer.parseInt(props.getProperty("security.api.groups.grs.conntimeout")));
		this.cache = new ConcurrentHashMap();
		logger.info(new FedExLogEntry("Group cache initialized"));
	}

	private static final class GroupsCachePersonMajorLazyHolder {
		private static GroupsCachePersonMajorLazy instance = null;

		public static GroupsCachePersonMajorLazy getInstance() {
			if (instance == null) {
				instance = new GroupsCachePersonMajorLazy(null);
			}
			return instance;
		}

		public static GroupsCachePersonMajorLazy getInstance(String propsFile) {
			if (instance == null) {
				instance = new GroupsCachePersonMajorLazy(propsFile);
			}
			return instance;
		}
	}

	public static final GroupsCachePersonMajorLazy getInstance() {
		logger.trace(new FedExLogEntry("GroupsCachePersonMajorLazy instance returned"));
		return GroupsCachePersonMajorLazyHolder.getInstance();
	}

	public static final GroupsCachePersonMajorLazy getInstance(String propsFile) {
		logger.trace(new FedExLogEntry("GroupsCachePersonMajorLazy instance w/ props file returned"));
		return GroupsCachePersonMajorLazyHolder.getInstance(propsFile);
	}

	private void startTimer() {
		if (this.timer != null) {
			this.timer.cancel();
		}
		this.timer = null;
		this.timer = new Timer(true);
		this.timer.schedule(new CacheRefreshTask(), this.refreshFrequency, this.refreshFrequency);
	}

	private void refreshGroups() {
		if (this.cache.size() > 0) {
			for (String uid : this.cache.keySet()) {
				cacheGroupsFor(uid);
			}
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
		String groups;
		if ((groupNames != null) && (groupNames.size() > 0)) {
			groups = this.cache.get(uid);
			if (groups == null) {
				cacheGroupsFor(uid);
				groups = this.cache.get(uid);
			}
			if (groups != null) {
				for (String groupName : groupNames) {
					if (groups.indexOf(":" + groupName + ":") > -1) {
						inGroup = true;
						break;
					}
				}
			}
		}
		return inGroup;
	}

	private String cacheGroupsFor(String uid) {
		HttpURLConnection conn = null;
		DataOutputStream dos = null;
		BufferedReader in = null;
		String groups = null;
		try {
			URL url = new URL(this.grsUrl);
			if ((uid != null) && (!"".equals(uid.trim()))) {
				conn = (HttpURLConnection)url.openConnection();
				conn.setDoInput(true);
				conn.setDoOutput(true);
				conn.setUseCaches(false);
				conn.setRequestMethod("POST");
				conn.setRequestProperty("Connection", "Keep-Alive");
				conn.setReadTimeout(this.grsReadTimeout);
				conn.setConnectTimeout(this.grsConnTimeout);
				dos = new DataOutputStream(conn.getOutputStream());
				dos.writeBytes("uid=" + URLEncoder.encode(uid, "UTF-8"));
				dos.flush();
				dos.close();
				dos = null;
				in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
				groups = "";
				String str;
				while ((str = in.readLine()) != null) {
					groups = groups + str;
					str = null;
				}
				if (GRSErrorCodes.ignoreErrorList.contains(groups)) {
					logger.warn(new FedExLogEntry("unexpected result from GRS for uid=" + uid + ", skipping cache update"));
				}
				else {
					this.cache.put(uid.intern(), (":" + groups + ":").intern());
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
//			if (this.timer != null) {
//				break label665;
//			}
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Error refreshing group cache from GRS"), e);
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
		startTimer();
		this.lastRefreshDate = new Date();
		label665:
		return !"".equals(groups.trim()) ? groups : null;
	}

	private class CacheRefreshTask
			extends TimerTask {
		private CacheRefreshTask() {
		}

		public void run() {
			GroupsCachePersonMajorLazy.getInstance().refreshGroups();
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
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\server\GroupsCachePersonMajorLazy.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */