package com.fedex.security.common;

import java.util.Arrays;
import java.util.List;

public class GRSErrorCodes {
	public static final String ERR_LDAP_UNAVAILABLE = "Error[01]:LDAP_Unavailable";
	public static final String ERR_DB_UNAVAILABLE = "Error[02]:Database_Unavailable";
	public static final String ERR_LDAP_TIMEOUT = "Error[03]:LDAP_Search_Timeout";
	public static final String ERR_NO_USER_PARAM = "Error[04]:No_UID_Specified";
	public static final String ERR_USER_NOT_IN_LDAP = "Error[05]:UID_Not_Found_In_LDAP";
	public static final String ERR_USER_EMPLOYMENT_STATUS = "Error[06]:User_Employment_Status_Invalid";
	public static final String ERR_USER_SOX_STATUS = "Error[07]:User_Sox_Status_Access_Denied";
	public static final String ERR_UNKNOWN_ERROR = "Error[08]:Unknown_Error";
	public static final List<String> ignoreErrorList = Arrays.asList("Error[01]:LDAP_Unavailable", "Error[02]:Database_Unavailable", "Error[03]:LDAP_Search_Timeout", "Error[04]:No_UID_Specified", "Error[08]:Unknown_Error");
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\common\GRSErrorCodes.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */