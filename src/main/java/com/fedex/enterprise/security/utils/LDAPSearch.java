package com.fedex.enterprise.security.utils;

import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSchema;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.factory.JSSESocketFactory;

import javax.annotation.PostConstruct;
import javax.naming.directory.BasicAttribute;
import java.util.ArrayList;
import java.util.Enumeration;

public class LDAPSearch {
	private boolean connected = false;
	private boolean running = true;
	private boolean reconnecting = false;
	private LDAPConnection ldapConnection = null;
	private final FedExLoggerInterface logger = FedExLogger.getLogger(LDAPSearch.class);
	private String baseDN;
	private String peopleBaseDN;
	private String groupBaseDN;
	private String ldapServer;
	private int ldapPort;
	private int ldapResultSize;
	private int ldapBatchSize;
	private int ldapReConnInterval;
	private int ldapConnectTimeout;
	private int ldapSearchTimeout;
	private String usr;
	private String pswd;
	private final int lastResponse = 0;

	public LDAPConnection getLdapConnection() {
		return this.ldapConnection;
	}

	public void setLdapConnection(LDAPConnection ldapConnection) {
		this.ldapConnection = ldapConnection;
	}

	public String getBaseDN() {
		return this.baseDN;
	}

	public void setBaseDN(String baseDN) {
		this.baseDN = baseDN;
	}

	public String getPeopleBaseDN() {
		return this.peopleBaseDN;
	}

	public void setPeopleBaseDN(String peopleBaseDN) {
		this.peopleBaseDN = peopleBaseDN;
	}

	public String getGroupBaseDN() {
		return this.groupBaseDN;
	}

	public void setGroupBaseDN(String groupBaseDN) {
		this.groupBaseDN = groupBaseDN;
	}

	public String getLdapServer() {
		return this.ldapServer;
	}

	public void setLdapServer(String ldapServer) {
		this.ldapServer = ldapServer;
	}

	public int getLdapPort() {
		return this.ldapPort;
	}

	public void setLdapPort(int ldapPort) {
		this.ldapPort = ldapPort;
	}

	public int getLdapResultSize() {
		return this.ldapResultSize;
	}

	public void setLdapResultSize(int ldapResultSize) {
		this.ldapResultSize = ldapResultSize;
	}

	public int getLdapBatchSize() {
		return this.ldapBatchSize;
	}

	public void setLdapBatchSize(int ldapBatchSize) {
		this.ldapBatchSize = ldapBatchSize;
	}

	public int getLdapReConnInterval() {
		return this.ldapReConnInterval;
	}

	public void setLdapReConnInterval(int ldapReConnInterval) {
		this.ldapReConnInterval = ldapReConnInterval;
	}

	public int getLdapConnectTimeout() {
		return this.ldapConnectTimeout;
	}

	public void setLdapConnectTimeout(int ldapConnectTimeout) {
		this.ldapConnectTimeout = ldapConnectTimeout;
	}

	public int getLdapSearchTimeout() {
		return this.ldapSearchTimeout;
	}

	public void setLdapSearchTimeout(int ldapSearchTimeout) {
		this.ldapSearchTimeout = ldapSearchTimeout;
	}

	public String getUsr() {
		return this.usr;
	}

	public void setUsr(String usr) {
		this.usr = usr;
	}

	public String getPswd() {
		return this.pswd;
	}

	public void setPswd(String pswd) {
		this.pswd = pswd;
	}

	public void init() {
	}

	public LDAPSearch() {
		try {
			if (!initLdapConnection()) {
				this.logger.warn(new FedExLogEntry("LDAP connection is unavailable, retrying in " + this.ldapReConnInterval + "seconds."));
			}
		}
		catch (Exception e2) {
			this.logger.warn(new FedExLogEntry("Exception trying to connect to " + this.ldapServer), e2);
		}
	}

	@PostConstruct
	public boolean initLdapConnection() {
		try {
			this.ldapConnection = new LDAPConnection(new JSSESocketFactory(null));
			this.ldapConnection.setConnSetupDelay(0);
			this.ldapConnection.setConnectTimeout(5);
			this.ldapConnection.connect(this.ldapServer, this.ldapPort, this.usr, this.pswd);
			this.ldapConnection.setOption(3, new Integer(this.ldapResultSize));
			this.ldapConnection.setOption(20, new Integer(this.ldapBatchSize));
			this.ldapConnection.setOption(4, new Integer(this.ldapSearchTimeout * 1000));
			this.connected = this.ldapConnection.isConnected();
			if (this.connected) {
				this.logger.info(new FedExLogEntry("LDAP Connection established to " + this.ldapConnection.getHost()));
			}
		}
		catch (Exception e) {
			this.logger.warn(new FedExLogEntry("Unable to establish a connection to one of the LDAP servers: " + this.ldapServer));
			this.connected = false;
		}
		return this.connected;
	}

	public LDAPConnection getLDAPConnection() {
		LDAPConnection ldc = null;
		try {
			do {
				if (this.ldapConnection != null) {
					ldc = (LDAPConnection)this.ldapConnection.clone();
				}
				if ((ldc == null) || (!ldc.isConnected())) {
					if (!this.reconnecting) {
						this.reconnecting = true;
						this.logger.warn(new FedExLogEntry("Trying to establish a connection to LDAP server " + this.ldapServer));
						while (!initLdapConnection()) {
							Thread.sleep(this.ldapReConnInterval * 1000);
							this.logger.warn(new FedExLogEntry("Trying to establish a connection to LDAP server " + this.ldapServer));
						}
					}
					this.logger.warn(new FedExLogEntry("Unable to establish a connection to one of the LDAP servers: " + this.ldapServer));
				}
				if (ldc.isConnected()) {
					this.connected = true;
					this.reconnecting = false;
				}
			}
			while (!this.connected);
		}
		catch (Exception e) {
			this.logger.warn(new FedExLogEntry("[Error] - Could not retrieve an LDAP Connection from the pool"));
		}
		return ldc;
	}

	public ArrayList<BasicAttribute> getAllLdapAttributes()
			throws LDAPException {
		ArrayList<BasicAttribute> attribs = new ArrayList();
		LDAPSchema dirSchema = new LDAPSchema();
		dirSchema.fetchSchema(this.ldapConnection);
		this.logger.debug("Retrieving attribute names");
		Enumeration enumAttr = dirSchema.getAttributeNames();
		while (enumAttr.hasMoreElements()) {
			BasicAttribute attribute = new BasicAttribute((String)enumAttr.nextElement());
			attribs.add(attribute);
		}
		if (attribs.isEmpty()) {
			this.logger.warn("LDAPSearch is returning null attribs");
			return null;
		}
		this.logger.debug("Attributes successfully retrieved, returning");
		return attribs;
	}

	public LDAPUserRecord getUserAttribs(String uid) {
		String[] attrNames = {"uid", "nickname", "givenName", "sn", "objectclass"};
		return getUserAttribs(uid, attrNames);
	}

	public LDAPUserRecord getUserAttribs(String uid, String[] attrNames) {
		LDAPUserRecord userRecord = new LDAPUserRecord();
		LDAPConnection con = getLDAPConnection();
		String filter = "(uid=" + uid + ")";
		this.logger.debug(new FedExLogEntry("The current filter = " + filter));
		LDAPSearchResults answer = null;
		try {
			answer = con.search(this.peopleBaseDN, 1, filter, attrNames, false);
			if (answer != null) {
				Enumeration<LDAPAttribute> attrEn;
				while ((answer.hasMoreElements()) && (this.running)) {
					LDAPEntry entry = answer.next();
					LDAPAttributeSet attribSet = entry.getAttributeSet();
					userRecord = new LDAPUserRecord();
					for (attrEn = attribSet.getAttributes(); attrEn.hasMoreElements(); ) {
						LDAPAttribute attrib = attrEn.nextElement();
						String attribName = attrib.getName();
						if (attrib.size() > 0) {
							String[] values = attrib.getStringValueArray();
							if ("uid".equalsIgnoreCase(attribName)) {
								userRecord.setUid(values[0]);
							}
							else {
								if ("sn".equalsIgnoreCase(attribName)) {
									userRecord.setLastName(values[0]);
								}
								else {
									if ("nickname".equalsIgnoreCase(attribName)) {
										userRecord.setNickName(values[0]);
									}
									else {
										if ("givenName".equalsIgnoreCase(attribName)) {
											userRecord.setFirstName(values[0]);
										}
										else {
											if ("manager".equalsIgnoreCase(attribName)) {
												int startIndex = values[0].indexOf("uid") + 4;
												int endIndex = values[0].indexOf(",");
												String manager = values[0].substring(startIndex, endIndex);
												userRecord.setManager(manager);
											}
											else {
												if ("objectclass".equalsIgnoreCase(attribName)) {
													for (String value : values) {
														if ("fxsystemaccount".equals(value)) {
															userRecord.setApplication(true);
															break;
														}
													}
													if (!userRecord.isApplication) {
														userRecord.setHuman(true);
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
		catch (LDAPException ldape) {
			this.logger.warn(new FedExLogEntry("Trying to find out about " + uid + ", but ran into trouble:" + ldape.toString()));
		}
		answer = null;
		try {
			con.disconnect();
		}
		catch (LDAPException e) {
			this.logger.warn(new FedExLogEntry(e.toString()));
		}
		return userRecord;
	}

	public ArrayList<String> getGroupNames(String groupName) {
		String[] attrNames = {"cn"};
		return getGroupNames(groupName, attrNames);
	}

	public ArrayList<String> getGroupNames(String groupName, String[] attrNames) {
		LDAPConnection con = getLDAPConnection();
		ArrayList<String> groups = new ArrayList();
		String filter = "(&(!(objectclass=inetmailgroup))(cn=" + groupName + "*))";
		this.logger.info(new FedExLogEntry("The current filter = " + filter));
		LDAPSearchResults answer = null;
		try {
			answer = con.search(this.groupBaseDN, 1, filter, attrNames, false);
			if (answer != null) {
				this.logger.info(new FedExLogEntry(answer.getCount() + " groups were found in LDAP for the search: " + groupName));
				Enumeration<LDAPAttribute> attrEn;
				while ((answer.hasMoreElements()) && (this.running)) {
					LDAPEntry entry = answer.next();
					LDAPAttributeSet attribSet = entry.getAttributeSet();
					for (attrEn = attribSet.getAttributes(); attrEn.hasMoreElements(); ) {
						LDAPAttribute attrib = attrEn.nextElement();
						String attribName = attrib.getName();
						if (attrib.size() > 0) {
							String[] values = attrib.getStringValueArray();
							if ("cn".equalsIgnoreCase(attribName)) {
								String name = values[0];
								this.logger.info(new FedExLogEntry("Group: " + name));
								groups.add(name);
							}
						}
					}
				}
			}
		}
		catch (LDAPException ldape) {
			this.logger.warn(new FedExLogEntry(ldape.toString()));
		}
		answer = null;
		try {
			con.disconnect();
		}
		catch (LDAPException e) {
			this.logger.warn(new FedExLogEntry(e.toString()));
		}
		return groups;
	}

	public boolean isConnected() {
		return this.connected;
	}

	public void shutdown() {
		this.running = false;
	}

	public String getLdapServerName() {
		return this.ldapConnection.getHost();
	}

	public int getLastResponseTime() {
		getClass();
		return 0;
	}

	public void destroy() {
		try {
			this.ldapConnection.disconnect();
		}
		catch (Exception e) {
			this.logger.error(new FedExLogEntry("Caught General Exception in destroy from LDAPSearch"), e);
		}
	}

	public ArrayList<String> getExactGroupNames(String groupName) {
		String[] attrNames = {"cn"};
		return getExactGroupNames(groupName, attrNames);
	}

	public ArrayList<String> getExactGroupNames(String groupName, String[] attrNames) {
		LDAPConnection con = getLDAPConnection();
		ArrayList<String> groups = new ArrayList();
		String filter = "(&(!(objectclass=inetmailgroup))(cn=" + groupName + ")";
		this.logger.info(new FedExLogEntry("The current filter = " + filter));
		LDAPSearchResults answer = null;
		try {
			answer = con.search(this.groupBaseDN, 1, filter, attrNames, false);
			if (answer != null) {
				this.logger.info(new FedExLogEntry(answer.getCount() + " groups were found in LDAP for the search: " + groupName));
				while ((answer.hasMoreElements()) && (this.running)) {
					LDAPEntry entry = answer.next();
					LDAPAttributeSet attribSet = entry.getAttributeSet();
					Enumeration<LDAPAttribute> attrEn = attribSet.getAttributes();
					while (attrEn.hasMoreElements()) {
						LDAPAttribute attrib = attrEn.nextElement();
						String attribName = attrib.getName();
						if (attrib.size() > 0) {
							String[] values = attrib.getStringValueArray();
							if ("cn".equalsIgnoreCase(attribName)) {
								String name = values[0];
								this.logger.info(new FedExLogEntry("Group: " + name));
								groups.add(name);
							}
						}
					}
				}
			}
		}
		catch (LDAPException ldape) {
			this.logger.warn(new FedExLogEntry(ldape.toString()));
		}
		answer = null;
		try {
			con.disconnect();
		}
		catch (LDAPException e) {
			this.logger.warn(new FedExLogEntry(e.toString()));
		}
		return groups;
	}
}
