package com.fedex.enterprise.security.role;

import com.fedex.cds.Bookmark;
import com.fedex.enterprise.security.role.restriction.RestrictionData;

import java.util.List;

public interface RoleService {
	List<RoleData> getRolesForApplication(String paramString);

	List<RoleData> getRolesForApplication(String paramString, boolean paramBoolean);

	List<RoleData> getRolesForApplicationByPartialRoleName(String paramString1, String paramString2);

	List<RoleData> getRoleForApplicationByRoleName(String paramString1, String paramString2);

	RoleData getRoleForApplicationByRoleName(String paramString1, String paramString2, boolean paramBoolean1, boolean paramBoolean2, Bookmark paramBookmark);

	RoleData getRoleByKey(long paramLong);

	RoleData getRoleByKey(long paramLong, boolean paramBoolean);

	List<GroupRoleData> getGroupMembersForRoleByKey(long paramLong);

	List<UserRoleData> getUserMembersForRoleByKey(long paramLong);

	List<AppRoleData> getApplicationMembersForRoleByKey(long paramLong);

	List<UserRoleData> getRoleOwners(long paramLong);

	List<RoleData> getRolesOfUser(String paramString);

	long insertRole(RoleData paramRoleData);

	void updateRole(RoleData paramRoleData);

	long updateRoleGroupsForApplication(GroupRoleData paramGroupRoleData, long paramLong);

	long updateRoleUsersForApplication(UserRoleData paramUserRoleData, long paramLong);

	long updateRoleAppsForApplication(AppRoleData paramAppRoleData, long paramLong);

	void deleteRoleForApplicationByKey(long paramLong);

	void deleteRoleGroupForApplicationByKey(long paramLong);

	void deleteRoleUserForApplicationByKey(long paramLong);

	void deleteRoleApplicationForApplicationByKey(long paramLong);

	List<RestrictionData> getRestrictionsForApplication(String paramString, Bookmark paramBookmark);

	void deleteRestriction(RestrictionData paramRestrictionData);

	long insertRestriction(RestrictionData paramRestrictionData);

	List<RestrictionData> getRestrictionsForRole(String paramString1, String paramString2, Bookmark paramBookmark);

	RestrictionData restrieveRestrictionByKey(long paramLong);

	List<RestrictionData> getRestrictionsForUserOrGrp(String paramString1, String paramString2, String paramString3);

	long updateRoleUsersForApplication(UserRoleData paramUserRoleData, long paramLong, boolean paramBoolean, String paramString1, String paramString2);

	long updateRoleGroupsForApplication(GroupRoleData paramGroupRoleData, long paramLong, boolean paramBoolean, String paramString1, String paramString2);
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\role\RoleService.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */