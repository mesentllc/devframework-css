package com.fedex.enterprise.security.api;

import com.fedex.enterprise.security.role.RoleData;
import com.fedex.enterprise.security.role.restriction.RestrictionData;
import com.fedex.enterprise.security.rule.RuleData;

import java.util.List;

public interface SecurityService {
	List<RuleData> getRulesForApplicationAPI(String paramString);

	List<RoleData> getRolesForApplicationAPI(String paramString);

	List<RestrictionData> getRestrictionsOnRoles(String paramString);

	List<RoleData> getAllRolesForApplicationAPI(List<Long> paramList, String paramString);
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\api\SecurityService.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */