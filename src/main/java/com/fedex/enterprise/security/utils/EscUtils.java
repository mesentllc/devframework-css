package com.fedex.enterprise.security.utils;

import com.fedex.cds.Bookmark;
import com.fedex.cds.CdsSecurityAction;
import com.fedex.cds.CdsSecurityResource;
import com.fedex.cds.CdsSecurityRole;
import com.fedex.cds.CdsSecurityRule;
import com.fedex.ea.framework.securityapi.dao.esc.EscDaoException;
import com.fedex.enterprise.security.action.ActionData;
import com.fedex.enterprise.security.group.LdapAttribute;
import com.fedex.enterprise.security.group.SalesTerritoryRangeData;
import com.fedex.enterprise.security.resource.ResourceData;
import com.fedex.enterprise.security.role.GroupRoleData;
import com.fedex.enterprise.security.role.RoleData;
import com.fedex.enterprise.security.role.UserRoleData;
import com.fedex.enterprise.security.role.restriction.Entry;
import com.fedex.enterprise.security.role.restriction.RestrictionDataItem;
import com.fedex.enterprise.security.role.restriction.RestrictionSequence;
import com.fedex.enterprise.security.rule.RuleData;
import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import com.fedex.framework.utility.FedExAppFrameworkProperties;
import com.fedex.security.common.StringUtils;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import java.math.BigInteger;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

public class EscUtils {
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(EscUtils.class);

	public String formatAppId(String appId) {
		if ((appId != null) && (!appId.trim().isEmpty())) {
			String formatAppId = appId.trim();
			if (formatAppId.length() >= 4) {
				return formatAppId;
			}
			if (formatAppId.length() == 3) {
				return formatAppId;
			}
			if (formatAppId.length() == 2) {
				return formatAppId;
			}
			return formatAppId;
		}
		return appId;
	}

	public static String formatStaticAppId(String appId) {
		if ((appId != null) && (!appId.trim().isEmpty())) {
			String formatAppId = appId.trim();
			if (formatAppId.length() >= 4) {
				return appId;
			}
			if (formatAppId.length() == 3) {
				return formatAppId;
			}
			if (formatAppId.length() == 2) {
				return formatAppId;
			}
			return formatAppId;
		}
		return appId;
	}

	public static boolean isNullOrBlank(String s) {
		boolean result = true;
		if ((s != null) && (s.trim().length() > 0)) {
			result = false;
		}
		return result;
	}

	public static boolean isOneOf(String s, String... checkList) {
		if (isNullOrBlank(s)) {
			return false;
		}
		if (checkList != null) {
			for (String check : checkList) {
				if (s.equalsIgnoreCase(check)) {
					return true;
				}
			}
		}
		return false;
	}

	public void checkResource(ResourceData resourceData) {
		try {
			if (resourceData.isRoot()) {
				resourceData.setRootFlg('Y');
				String resName = resourceData.getResName();
				if ((!resName.endsWith("/")) && (!resName.endsWith("*"))) {
					resName = resName + "/";
				}
				resourceData.setResName(resName);
			}
		}
		catch (Exception e) {
		}
	}

	public static long getActionDocIdbyName(String actionName, String appId) {
		long actionDocId = 0L;
		CdsSecurityAction cdsAction = new CdsSecurityAction();
		ActionData actionData = null;
		try {
			actionData = cdsAction.retrieveByName(actionName, appId);
			if (actionData != null) {
				actionDocId = actionData.getDocId();
			}
		}
		catch (EscDaoException e) {
			logger.warn("Querying for action name '" + actionName + "' for application " + appId + " threw an error.", e);
		}
		return actionDocId;
	}

	public static long getRoleDocIdbyName(String roleName, String appId) {
		long roleDocId = 0L;
		RoleData roleData = CdsSecurityRole.RetrieveByRoleName(roleName, appId, false, false, null);
		if (roleData != null) {
			roleDocId = roleData.getDocId();
		}
		return roleDocId;
	}

	public static long getResourceDocIdbyName(String resName, String appId) {
		long resDocId = 0L;
		CdsSecurityResource cdsSecurityResource = new CdsSecurityResource();
		ResourceData resData = cdsSecurityResource.getResourceByName(appId, resName);
		if (resData != null) {
			resDocId = resData.getDocId();
		}
		return resDocId;
	}

	public static String getRuleNameByDocId(long ruleDocId, String appId) {
		RuleData ruleData = CdsSecurityRule.Retrieve(ruleDocId);
		long actionDocId = 0L;
		long resDocId = 0L;
		long roleDocId = 0L;
		String actionName = "";
		String roleName = "";
		String resNm = "";
		String grantMsg = "";
		ActionData actData = null;
		ResourceData resData = null;
		String ruleNm = "";
		RoleData roleData = null;
		if (ruleData != null) {
			actionDocId = ruleData.getActionDocId();
			roleDocId = ruleData.getRoleDocId();
			resDocId = ruleData.getResDocId();
			resData = CdsSecurityResource.getResourceByKey(Long.valueOf(resDocId));
			actData = CdsSecurityAction.getActionByKey(Long.valueOf(actionDocId));
			roleData = CdsSecurityRole.Retrieve(roleDocId, false);
			grantMsg = ruleData.getGrantMsg();
		}
		if (roleData != null) {
			roleName = roleData.getRoleNm();
		}
		if (actData != null) {
			actionName = actData.getActionNm();
		}
		if (resData != null) {
			resNm = resData.getResName();
		}
		ruleNm = roleName + " " + grantMsg + " " + actionName + " " + resNm;
		return ruleNm;
	}

	public static RuleData getRuleNameByDocId(long ruleDocId) {
		RuleData ruleData = CdsSecurityRule.Retrieve(ruleDocId);
		long actionDocId = 0L;
		long resDocId = 0L;
		long roleDocId = 0L;
		String grantMsg = "";
		ActionData actData = null;
		ResourceData resData = null;
		RoleData roleData = null;
		if (ruleData != null) {
			actionDocId = ruleData.getActionDocId();
			roleDocId = ruleData.getRoleDocId();
			resDocId = ruleData.getResDocId();
			resData = CdsSecurityResource.getResourceByKey(Long.valueOf(resDocId));
			actData = CdsSecurityAction.getActionByKey(Long.valueOf(actionDocId));
			roleData = CdsSecurityRole.Retrieve(roleDocId, false);
			grantMsg = ruleData.getGrantMsg();
		}
		if (roleData != null) {
			ruleData.setRoleNm(roleData.getRoleNm());
		}
		if (actData != null) {
			ruleData.setActionNm(actData.getActionNm());
		}
		if (resData != null) {
			ruleData.setResourceNm(resData.getResName());
		}
		return ruleData;
	}

	public static List<String> getRoleMembers(long roleDocId) {
		List<String> uids = new ArrayList();
		List<String> groups = new ArrayList();
		GrsUtils grsUtils = new GrsUtils();
		RoleData role = CdsSecurityRole.Retrieve(roleDocId, true);
		if ((role != null) && (role.getGroupMemberList() != null) && (role.getGroupMemberList().size() > 0)) {
			for (GroupRoleData groupRole : role.getGroupMemberList()) {
				groups.add(groupRole.getGroupNm());
			}
		}
		if ((role != null) && (role.getUserMemberList() != null) && (role.getUserMemberList().size() > 0)) {
			for (UserRoleData userRole : role.getUserMemberList()) {
				uids.add(userRole.getEmpNbr());
			}
		}
		for (String group : groups) {
			List<String> members = grsUtils.getMembersOfGroup(group);
			for (String member : members) {
				uids.add(member);
			}
		}
		return uids;
	}

	public static String getExtRuleNameByDocId(long extRuleDocId, String appId) {
		String ruleNm = "";
		return "";
	}

	public static boolean salesTerritoryDuplicateCheck(LdapAttribute grData, LdapAttribute currentAttrib) {
		SalesTerritoryRangeData existing = grData.getTtyData();
		SalesTerritoryRangeData current = currentAttrib.getTtyData();
		boolean isDuplicate = false;
		boolean isSalesDivDuplicate = false;
		boolean isSalesGrpDuplicate = false;
		boolean isSalesOrgDuplicate = false;
		boolean isSalesRegionDuplicate = false;
		boolean isSalesAreaDuplicate = false;
		boolean isSalesDistDuplicate = false;
		boolean isSalesTerrDuplicate = false;
		String salesDuplicate = "";
		if (grData.getOpco().equalsIgnoreCase(currentAttrib.getOpco())) {
			if (!isNullOrBlank(current.getSalesDivNbrFrom())) {
				isSalesDivDuplicate = genericDuplicateCheck(existing.getSalesDivNbrFrom(), existing.getSalesDivNbrTo(), current.getSalesDivNbrFrom(), current.getSalesDivNbrTo());
				salesDuplicate = salesDuplicate + isSalesDivDuplicate;
			}
			else {
				if (current.getSalesDivNbrFrom().equalsIgnoreCase("")) {
					isSalesDivDuplicate = genericBlankCheck(existing.getSalesDivNbrFrom(), current.getSalesDivNbrFrom());
					salesDuplicate = salesDuplicate + isSalesDivDuplicate;
				}
			}
			if (!isNullOrBlank(current.getSalesGrpNbrFrom())) {
				isSalesGrpDuplicate = genericDuplicateCheck(existing.getSalesGrpNbrFrom(), existing.getSalesGrpNbrTo(), current.getSalesGrpNbrFrom(), current.getSalesGrpNbrTo());
				salesDuplicate = salesDuplicate + isSalesGrpDuplicate;
			}
			else {
				if (current.getSalesGrpNbrFrom().equalsIgnoreCase("")) {
					isSalesGrpDuplicate = genericBlankCheck(existing.getSalesGrpNbrFrom(), current.getSalesGrpNbrFrom());
					salesDuplicate = salesDuplicate + isSalesGrpDuplicate;
				}
			}
			if (!isNullOrBlank(current.getSalesOrgNbrFrom())) {
				isSalesOrgDuplicate = genericDuplicateCheck(existing.getSalesOrgNbrFrom(), existing.getSalesOrgNbrTo(), current.getSalesOrgNbrFrom(), current.getSalesOrgNbrTo());
				salesDuplicate = salesDuplicate + isSalesOrgDuplicate;
			}
			else {
				if (current.getSalesOrgNbrFrom().equalsIgnoreCase("")) {
					isSalesOrgDuplicate = genericBlankCheck(existing.getSalesOrgNbrFrom(), current.getSalesOrgNbrFrom());
					salesDuplicate = salesDuplicate + isSalesOrgDuplicate;
				}
			}
			if (!isNullOrBlank(current.getSalesAreaNbrFrom())) {
				isSalesAreaDuplicate = genericDuplicateCheck(existing.getSalesAreaNbrFrom(), existing.getSalesAreaNbrTo(), current.getSalesAreaNbrFrom(), current.getSalesAreaNbrTo());
				salesDuplicate = salesDuplicate + isSalesAreaDuplicate;
			}
			else {
				if (current.getSalesAreaNbrFrom().equalsIgnoreCase("")) {
					isSalesAreaDuplicate = genericBlankCheck(existing.getSalesAreaNbrFrom(), current.getSalesAreaNbrFrom());
					salesDuplicate = salesDuplicate + isSalesAreaDuplicate;
				}
			}
			if (!isNullOrBlank(current.getSalesRegionNbrFrom())) {
				isSalesRegionDuplicate = genericDuplicateCheck(existing.getSalesRegionNbrFrom(), existing.getSalesRegionNbrTo(), current.getSalesRegionNbrFrom(), current.getSalesRegionNbrTo());
				salesDuplicate = salesDuplicate + isSalesRegionDuplicate;
			}
			else {
				if (current.getSalesRegionNbrFrom().equalsIgnoreCase("")) {
					isSalesRegionDuplicate = genericBlankCheck(existing.getSalesRegionNbrFrom(), current.getSalesRegionNbrFrom());
					salesDuplicate = salesDuplicate + isSalesRegionDuplicate;
				}
			}
			if (!isNullOrBlank(current.getSalesDistNbrFrom())) {
				isSalesDistDuplicate = genericDuplicateCheck(existing.getSalesDistNbrFrom(), existing.getSalesDistNbrTo(), current.getSalesDistNbrFrom(), current.getSalesDistNbrTo());
				salesDuplicate = salesDuplicate + isSalesDistDuplicate;
			}
			else {
				if (current.getSalesDistNbrFrom().equalsIgnoreCase("")) {
					isSalesDistDuplicate = genericBlankCheck(existing.getSalesDistNbrFrom(), current.getSalesDistNbrFrom());
					salesDuplicate = salesDuplicate + isSalesDistDuplicate;
				}
			}
			if (!isNullOrBlank(current.getSalesTtyNbrFrom())) {
				isSalesTerrDuplicate = genericDuplicateCheck(existing.getSalesTtyNbrFrom(), existing.getSalesTtyNbrTo(), current.getSalesTtyNbrFrom(), current.getSalesTtyNbrTo());
				salesDuplicate = salesDuplicate + isSalesTerrDuplicate;
			}
			else {
				if (current.getSalesTtyNbrFrom().equalsIgnoreCase("")) {
					isSalesTerrDuplicate = genericBlankCheck(existing.getSalesTtyNbrFrom(), current.getSalesTtyNbrFrom());
					salesDuplicate = salesDuplicate + isSalesTerrDuplicate;
				}
			}
			if (!salesDuplicate.contains("false")) {
				isDuplicate = true;
			}
		}
		return isDuplicate;
	}

	public static boolean withinRange(int from, int to, int current) {
		return (current >= from) && (current <= to);
	}

	public static boolean withinRange(int from, int to, String current) {
		if ((current == null) || (current.length() < 1)) {
			return false;
		}
		try {
			return withinRange(from, to, Integer.parseInt(current));
		}
		catch (NumberFormatException e) {
		}
		return false;
	}

	public static boolean genericBlankCheck(String existingFromVal, String currentFromVal) {
		boolean isDuplicate = false;
		if (existingFromVal == currentFromVal) {
			isDuplicate = true;
		}
		return isDuplicate;
	}

	public static boolean genericDuplicateCheck(String existingFromVal, String existingToVal, String currentFromVal, String currentToVal) {
		boolean isDuplicate = false;
		if ((!isNullOrBlank(existingToVal)) && (!"".equalsIgnoreCase(existingToVal))) {
			int existingTo = Integer.parseInt(existingToVal);
			int existingFrom = Integer.parseInt(existingFromVal);
			if ((!isNullOrBlank(currentToVal)) && (!"".equalsIgnoreCase(currentToVal))) {
				int currentFrom = Integer.parseInt(currentFromVal);
				int currentTo = Integer.parseInt(currentToVal);
				if ((currentFrom <= existingTo) && (currentTo >= existingFrom)) {
					isDuplicate = true;
				}
			}
			else {
				int currentFrom = Integer.parseInt(currentFromVal);
				if (withinRange(existingFrom, existingTo, currentFrom)) {
					isDuplicate = true;
				}
			}
		}
		else {
			if ((!isNullOrBlank(existingFromVal)) && (!isNullOrBlank(currentFromVal))) {
				int existingFrom = Integer.parseInt(existingFromVal);
				int currentFrom = Integer.parseInt(currentFromVal);
				if ((!isNullOrBlank(currentToVal)) && (!"".equalsIgnoreCase(currentToVal))) {
					int currentTo = Integer.parseInt(currentToVal);
					if (withinRange(currentFrom, currentTo, existingFrom)) {
						isDuplicate = true;
					}
				}
				else {
					if (existingFrom == currentFrom) {
						isDuplicate = true;
					}
				}
			}
		}
		return isDuplicate;
	}

	public static String retrieveEmpOrGroup(String desc) {
		String name = "";
		String phrase1 = " was";
		int indexOfPhrase1 = desc.indexOf(" was");
		name = desc.substring(0, indexOfPhrase1);
		return name;
	}

	public static String retrieveRoleName(String desc) {
		String roleName = "";
		String phrase1 = " the ";
		String phrase2 = " role";
		int indexOfPhrase1 = desc.indexOf(" the ");
		int indexOfPhrase2 = desc.indexOf(" role");
		roleName = desc.substring(indexOfPhrase1 + 4, indexOfPhrase2);
		return roleName;
	}

	public static XMLGregorianCalendar convertTimeStamptoXMLGregorianCalendar(Timestamp time) {
		Date date = new Date(time.getTime());
		GregorianCalendar gCalendar = new GregorianCalendar();
		gCalendar.setTime(date);
		XMLGregorianCalendar xmlCalendar = null;
		try {
			xmlCalendar = DatatypeFactory.newInstance().newXMLGregorianCalendar(gCalendar);
		}
		catch (DatatypeConfigurationException ex) {
			logger.error(new FedExLogEntry("Caught DatatypeConfigurationException in convertTimeStamptoXMLGregorianCalendar from EscUtils"), ex);
		}
		return xmlCalendar;
	}

	public static String levelCheck() {
		String level = "";
		if (FedExAppFrameworkProperties.getInstance().getEnvType() != null) {
			level = FedExAppFrameworkProperties.getInstance().getEnvType();
		}
		return level;
	}

	public static long getRoleDocIdByResource(long appId) {
		long resourceDocId = getResourceDocIdbyName(appId + "/*", "4112");
		List<RuleData> rules = CdsSecurityRule.RetrieveByResourceDocIdHflow(resourceDocId, new Bookmark());
		if (rules != null) {
			for (RuleData rule : rules) {
				if ((rule.getResourceNm() != null) && (rule.getActionNm().equals("*")) && ("Y".equals(Character.valueOf(rule.getGrantFlg())))) {
					return rule.getRoleDocId();
				}
			}
		}
		return 0L;
	}

	public static String convertCalendarToXMLString(Calendar c) {
		DatatypeFactory dataFactory = null;
		XMLGregorianCalendar cal = null;
		try {
			dataFactory = DatatypeFactory.newInstance();
			cal = dataFactory.newXMLGregorianCalendar();
			cal.setYear(c.get(1));
			cal.setMonth(c.get(2) + 1);
			cal.setDay(c.get(5));
			cal.setHour(c.get(11));
			cal.setMinute(c.get(12));
			cal.setSecond(c.get(13));
			cal.setMillisecond(c.get(14));
		}
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Unable to get the datatype factory to convert dates for the : " + e));
		}
		logger.info(new FedExLogEntry("Converted Calendar to XML String: " + cal.toString()));
		return cal.toString();
	}

	public List<RestrictionDataItem> addRestrictionDataItemIndex(List<RestrictionDataItem> restrictionDataItemList, RestrictionSequence restrictionSequence) {
		int listIndex = 0;
		BigInteger start = new BigInteger(restrictionSequence.getStartIndex());
		BigInteger end = new BigInteger(restrictionSequence.getEndIndex());
		BigInteger bigIncr = new BigInteger("1");
		while ((listIndex < restrictionDataItemList.size()) && (start.compareTo(end) <= 1)) {
			if (StringUtils.isNullOrBlank(restrictionDataItemList.get(listIndex).getRestrictionItemIndex())) {
				restrictionDataItemList.get(listIndex).setRestrictionItemIndex(start.toString());
				start = start.add(bigIncr);
			}
			listIndex++;
		}
		return restrictionDataItemList;
	}

	public boolean checkForRestrctionDataItemMatch(RestrictionDataItem fromUser, RestrictionDataItem fromCds) {
		if ((fromUser == null) && (fromCds == null)) {
			return true;
		}
		if ((fromUser == null) && (fromCds != null)) {
			return false;
		}
		if ((fromUser != null) && (fromCds == null)) {
			return false;
		}
		if ((fromUser.getEntry() == null) && (fromCds.getEntry() == null)) {
			return true;
		}
		if ((fromUser.getEntry() == null) && (fromCds.getEntry() != null)) {
			return false;
		}
		if (((fromUser.getEntry() != null ? 1 : 0) & (fromCds.getEntry() == null ? 1 : 0)) != 0) {
			return false;
		}
		return compareEntryList(fromUser.getEntry(), fromCds.getEntry());
	}

	public boolean checkForRestrctionMatch(List<RestrictionDataItem> itemListFromUser, List<RestrictionDataItem> itemListFromCDS) {
		boolean isNull = false;
		for (Iterator i$ = itemListFromCDS.iterator(); i$.hasNext(); ) {
			RestrictionDataItem item = (RestrictionDataItem)i$.next();
			for (RestrictionDataItem item1 : itemListFromUser) {
				if (item.getEntry() == null) {
					isNull = true;
				}
				else {
					isNull = false;
					if (compareEntryList(item1.getEntry(), item.getEntry())) {
						return true;
					}
					if (!isNull) {
					}
				}
			}
		}
		return false;
	}

	public boolean compareEntryList(List<Entry> entryFromUser, List<Entry> entryFromCds) {
		if ((entryFromUser == null) && (entryFromCds == null)) {
			return true;
		}
		if ((entryFromUser != null) && (entryFromCds == null)) {
			return false;
		}
		if ((entryFromUser == null) && (entryFromCds != null)) {
			return false;
		}
		if (entryFromUser.size() != entryFromCds.size()) {
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
				logger.error(new FedExLogEntry("Entry list has an entry with a null key/value. "));
			}
		}
		for (Entry entry : entryFromCds) {
			if (entry == null) {
				return false;
			}
			if ((entry.getKey() == null) || (entry.getValue() == null)) {
				logger.error(new FedExLogEntry("Entry list in the cache is null,there should be at least one entry item. "));
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

	public static String prependAPP(String id) {
		if (id == null) {
			return null;
		}
		if (!id.startsWith("APP")) {
			StringBuilder sb = new StringBuilder("APP");
			sb.append(id);
			return sb.toString();
		}
		return id;
	}
}
