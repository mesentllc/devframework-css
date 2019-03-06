package com.fedex.enterprise.security.utils;

import com.fedex.enterprise.security.group.GroupData;
import com.fedex.enterprise.security.group.GroupService;
import com.fedex.enterprise.security.rule.RuleData;
import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import com.fedex.symphony.ws.ApplicationBean;
import com.fedex.symphony.ws.GetApplications;
import com.fedex.symphony.ws.ProfileApplications;
import org.springframework.ws.client.core.WebServiceTemplate;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.List;

public class ValidationUtils {
	private static final String A_Z_A_Z0_9 = "[a-zA-Z0-9\\_\\-\\ ]+";
	private static final FedExLoggerInterface LOGGER = FedExLogger.getLogger(ValidationUtils.class);

	public static String validateActionNm(String inputValue) {
		String pattern = "[a-zA-Z0-9\\_\\-]+";
		String requiredMsg = "";
		if ((inputValue != null) && (!inputValue.equals("")) && (!inputValue.equals("*")) && (inputValue.length() < 3)) {
			requiredMsg = ErrorConstants.min_searchchars_required;
		}
		if ((inputValue != null) && (!inputValue.equals("")) && (inputValue.length() > 32)) {
			requiredMsg = ErrorConstants.max_action_length;
		}
		if ((inputValue != null) && (!inputValue.equals("")) && (!inputValue.equals("*")) && (!inputValue.matches("[a-zA-Z0-9\\_\\-]+"))) {
			requiredMsg = ErrorConstants.invalid_string;
		}
		if ((inputValue != null) && (!inputValue.equals("")) && (inputValue.length() > 50)) {
			requiredMsg = ErrorConstants.max_searchchars_required;
		}
		return requiredMsg;
	}

	public static String validateActionDesc(String inputValue) {
		String requiredMsg = "";
		String pattern = "[a-zA-Z0-9\\_\\-\\ ]+";
		if ((inputValue != null) && (!inputValue.matches("[a-zA-Z0-9\\_\\-\\ ]+"))) {
			requiredMsg = ErrorConstants.invalid_string;
		}
		if ((inputValue != null) && (!inputValue.equals("")) && (inputValue.length() > 75)) {
			requiredMsg = ErrorConstants.max_desc_allowed;
		}
		return requiredMsg;
	}

	public static String validateResourceNm(String inputValue) {
		String requiredMsg = "";
		String pattern = "[a-zA-Z0-9\\_\\-\\.]+";
		if ((inputValue != null) && (!inputValue.equals("")) && (!inputValue.equals("*")) && (inputValue.trim().length() < 2)) {
			requiredMsg = ErrorConstants.min_resource_name_required;
		}
		if ((inputValue != null) && (!inputValue.trim().equals("")) && (!inputValue.equals("*")) && (!inputValue.matches("[a-zA-Z0-9\\_\\-\\.]+"))) {
			requiredMsg = ErrorConstants.invalid_string;
		}
		if ((inputValue != null) && (!inputValue.equals("")) && (inputValue.length() > 50)) {
			requiredMsg = ErrorConstants.max_resource_length;
		}
		return requiredMsg;
	}

	public static String validateResourceDesc(String inputValue) {
		String requiredMsg = "";
		String pattern = "[a-zA-Z0-9\\_\\-\\ ]+";
		if ((inputValue != null) && (!inputValue.matches("[a-zA-Z0-9\\_\\-\\ ]+"))) {
			requiredMsg = ErrorConstants.invalid_string;
		}
		if ((inputValue != null) && (!inputValue.equals("")) && (inputValue.length() > 75)) {
			requiredMsg = ErrorConstants.max_desc_allowed;
		}
		return requiredMsg;
	}

	public static String validateRoleNm(String inputValue) {
		String requiredMsg = "";
		String pattern = "[a-zA-Z0-9\\_\\-]+";
		if ((inputValue != null) && (!inputValue.equals("")) && (!inputValue.equals("*")) && (inputValue.length() < 3)) {
			requiredMsg = ErrorConstants.min_searchchars_required;
		}
		if ((inputValue != null) && (!inputValue.equals("")) && (!inputValue.equals("*")) && (!inputValue.matches("[a-zA-Z0-9\\_\\-]+"))) {
			requiredMsg = ErrorConstants.invalid_string;
		}
		if ((inputValue != null) && (!inputValue.equals("")) && (inputValue.length() > 50)) {
			requiredMsg = ErrorConstants.max_searchchars_required;
		}
		return requiredMsg;
	}

	public static String validateRoleDesc(String inputValue) {
		String requiredMsg = "";
		String pattern = "[a-zA-Z0-9\\_\\-\\ ]+";
		if ((inputValue != null) && (!inputValue.matches("[a-zA-Z0-9\\_\\-\\ ]+"))) {
			requiredMsg = ErrorConstants.invalid_string;
		}
		if ((inputValue != null) && (!inputValue.equals("")) && (inputValue.length() > 75)) {
			requiredMsg = ErrorConstants.max_desc_allowed;
		}
		return requiredMsg;
	}

	public static String validateUserId(String inputValue, LDAPSearch ldapSearch) {
		String requiredMsg = "";
		String pattern = "\\*";
		if ((inputValue != null) && (!inputValue.equals(""))) {
			if (inputValue.trim().matches("\\*")) {
				requiredMsg = ErrorConstants.invalid_fedex_uid;
			}
			else {
				LDAPUserRecord record = ldapSearch.getUserAttribs(inputValue);
				if ((record.getUid() == null) || ("".equals(record.getUid().trim()))) {
					requiredMsg = ErrorConstants.invalid_fedex_uid;
				}
			}
		}
		return requiredMsg;
	}

	public static boolean isValidAppId(String inputValue, WebServiceTemplate webServiceTemplate) {
		boolean validFlg = false;
		String pattern = "[a-zA-Z0-9]+";
		if ((inputValue != null) && (!inputValue.equals("")) && (!inputValue.matches("[a-zA-Z0-9]+"))) {
			validFlg = false;
		}
		try {
			GetApplications applicationList = new GetApplications();
			List<Integer> appIds = new ArrayList();
			appIds.add(Integer.valueOf(Integer.parseInt(inputValue)));
			applicationList.getApplIDs().addAll(appIds);
			List<ProfileApplications> appIdData = SymphonyUtil.callSymphony().getApplications(appIds);
			if ((appIdData != null) && (!appIdData.isEmpty())) {
				for (ProfileApplications prflApp : appIdData) {
					List<ApplicationBean> appArray = prflApp.getApplications();
					if (appArray != null) {
						for (ApplicationBean appBean : appArray) {
							if ((appBean.getAppName() != null) && (appBean.getAppName() != "") && (appBean.getRetiredFlag() != null) && (appBean.getRetiredFlag().equals("N")) && (appBean.getDeletedFlag() != null) && (appBean.getDeletedFlag().equals("N"))) {
								validFlg = true;
							}
						}
					}
				}
			}
		}
		catch (Exception e) {
			LOGGER.error(new FedExLogEntry("Caught General Exception isValidAppId in Validation Utils"), e);
			e.getMessage();
		}
		return validFlg;
	}

	public static String validateSuperuserAccess(RuleData ruleData) {
		String requiredMsg = "";
		if (ruleData == null) {
			requiredMsg = ErrorConstants.null_value;
		}
		else {
			String resourceNm = ruleData.getResourceNm();
			String roleNm = ruleData.getRoleNm();
			String actionNm = ruleData.getActionNm();
			if ((actionNm != null) && (ErrorConstants.super_access.equals(actionNm.trim())) && (roleNm != null) && (ErrorConstants.super_access.equals(roleNm.trim())) && (((resourceNm != null) && (ErrorConstants.super_access.equals(resourceNm.trim()))) || ((resourceNm.trim().contains(ErrorConstants.esc_appid)) && (!resourceNm.trim().contains(ErrorConstants.esc_group)) && (!resourceNm.trim().contains(ErrorConstants.esc_report))))) {
				requiredMsg = ErrorConstants.invalid_rule;
			}
		}
		return requiredMsg;
	}

	public static String ruleValidation(RuleData ruleRequest, String appId) {
		String validationMsg = "";
		long roleDocId = EscUtils.getRoleDocIdbyName(ruleRequest.getRoleNm(), appId);
		long resourceDocId = EscUtils.getResourceDocIdbyName(ruleRequest.getResourceNm(), appId);
		long actionDocId = EscUtils.getActionDocIdbyName(ruleRequest.getActionNm(), appId);
		if (roleDocId == 0L) {
			validationMsg = validationMsg + ErrorConstants.invalid_role;
		}
		if (resourceDocId == 0L) {
			validationMsg = validationMsg + ErrorConstants.invalid_resource;
		}
		if (actionDocId == 0L) {
			validationMsg = validationMsg + ErrorConstants.invalid_action;
		}
		if ((roleDocId != 0L) && (resourceDocId != 0L) && (actionDocId != 0L)) {
			validationMsg = "";
		}
		return validationMsg;
	}

	public static String validateGroupNm(String grpNm, GroupService groupServiceImpl) {
		String validationMsg = "";
		try {
			GroupData groupData = groupServiceImpl.getGroupByName(grpNm, "446531");
			if (groupData == null) {
				validationMsg = ErrorConstants.invalid_grp;
			}
		}
		catch (Exception e) {
			if ((e.getMessage() != null) && (e.getMessage().equals("Group not found"))) {
				validationMsg = ErrorConstants.invalid_grp;
			}
			else {
				validationMsg = ErrorConstants.grp_create_err;
			}
		}
		return validationMsg;
	}

	public static boolean isGroupExist(String groupName, String ldapUrl, int urlConnectTimeout, int urlReadTimeout) {
		boolean exists = false;
		String request = ldapUrl + "?groupName=" + groupName + "&targetDataStore=1&groups_action=group_exists&loginFedExId=446531";
		try {
			URL url = new URL(request);
			URLConnection connection = url.openConnection();
			connection.setDoOutput(true);
			connection.setConnectTimeout(urlConnectTimeout);
			connection.setReadTimeout(urlReadTimeout);
			OutputStreamWriter out = new OutputStreamWriter(connection.getOutputStream());
			out.close();
			BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
			String inputLine;
			while ((inputLine = in.readLine()) != null) {
				if (inputLine.toLowerCase().equals("<result>true</result>")) {
					exists = true;
				}
			}
			in.close();
		}
		catch (Exception e) {
			throw new SecurityException("Problem retrieving group.", e);
		}
		return exists;
	}

	public static String validateClassNm(String inputValue) {
		String requiredMsg = "";
		String pattern = "[a-zA-Z0-9\\_\\-\\.\\$]+";
		if ((inputValue != null) && (!inputValue.equals("")) && (!inputValue.equals("*")) && (inputValue.length() < 2)) {
			requiredMsg = ErrorConstants.min_resource_name_required;
		}
		if ((inputValue != null) && (!inputValue.equals("")) && (!inputValue.equals("*")) && (!inputValue.matches("[a-zA-Z0-9\\_\\-\\.\\$]+"))) {
			requiredMsg = ErrorConstants.invalid_string;
		}
		if ((inputValue != null) && (!inputValue.equals("")) && (inputValue.length() > 96)) {
			requiredMsg = ErrorConstants.max_class_nm_length;
		}
		return requiredMsg;
	}

	public static String validateClassDesc(String inputValue) {
		String requiredMsg = "";
		String pattern = "[a-zA-Z0-9\\_\\-\\ ]+";
		if ((inputValue != null) && (!inputValue.matches("[a-zA-Z0-9\\_\\-\\ ]+"))) {
			requiredMsg = ErrorConstants.invalid_string;
		}
		if ((inputValue != null) && (!inputValue.equals("")) && (inputValue.length() > 40)) {
			requiredMsg = ErrorConstants.max_class_desc_allowed;
		}
		return requiredMsg;
	}
}
