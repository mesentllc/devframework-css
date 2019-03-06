package com.fedex.enterprise.security.group;

import com.fedex.enterprise.security.groups.FilterNode;
import com.fedex.enterprise.security.groups.Person;

import java.util.List;

public interface GroupService {
	GroupData getGroupByName(String paramString1, String paramString2);

	boolean groupExist(String paramString1, String paramString2);

	List<GroupData> getGroupsByPartialName(String paramString);

	boolean insertGroup(GroupData paramGroupData, String paramString);

	boolean updateGroup(GroupData paramGroupData, String paramString);

	List<Person> testGroup(GroupData paramGroupData, String paramString);

	List<Person> testGroupNoAttr(GroupData paramGroupData, String paramString);

	List<Person> findPeople(List<String> paramList);

	GroupMember getLdapUser(String paramString);

	boolean addStaticUserToGroup(String paramString1, String paramString2, String paramString3);

	boolean removeStaticUserFromGroup(String paramString1, String paramString2, String paramString3);

	FilterNode parseDynamicFilterString(String paramString);
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\group\GroupService.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */