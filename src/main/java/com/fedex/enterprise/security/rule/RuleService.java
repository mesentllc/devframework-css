package com.fedex.enterprise.security.rule;

import com.fedex.cds.Bookmark;
import com.fedex.enterprise.security.customauthz.CustomAuthzData;

import java.util.List;

public interface RuleService {
	List<RuleData> getRulesForApplication(String paramString, Bookmark paramBookmark);

	List<RuleData> getRulesForRole(long paramLong, Bookmark paramBookmark);

	List<RuleData> getRulesForResource(long paramLong, Bookmark paramBookmark);

	List<RuleData> getAccessListForId(String paramString1, String paramString2);

	List<ExtendedRuleData> getExtendedRulesForApplication(String paramString, Bookmark paramBookmark);

	List<ExtendedRuleData> getExtendedRulesForRuleId(long paramLong, Bookmark paramBookmark);

	List<ExtendedRuleXrefData> getExtendedRuleXrefForRuleId(long paramLong, Bookmark paramBookmark);

	void updateRule(RuleData paramRuleData);

	void deleteRuleByKey(long paramLong);

	void deleteRuleByKey(long paramLong, boolean paramBoolean, String paramString1, String paramString2);

	Long insertRule(RuleData paramRuleData);

	void addExtRule(ExtendedRuleXrefData paramExtendedRuleXrefData);

	void removeExtRule(Long paramLong);

	long insertExtRule(ExtendedRuleData paramExtendedRuleData);

	void updateExtRule(ExtendedRuleData paramExtendedRuleData);

	void deleteExtRuleByKey(long paramLong);

	long insertCustomAuthorizer(CustomAuthzData paramCustomAuthzData);

	List<CustomAuthzData> getCustAuthzsForApplication(String paramString, Bookmark paramBookmark);

	void deleteCustomAuthorizer(CustomAuthzData paramCustomAuthzData);

	void updateCustomAuthzr(CustomAuthzData paramCustomAuthzData);
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\rule\RuleService.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */