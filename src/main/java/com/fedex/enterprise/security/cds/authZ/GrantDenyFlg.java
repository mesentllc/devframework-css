package com.fedex.enterprise.security.cds.authZ;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlType;

@XmlType(name = "Grant_Deny_Flg")
@XmlEnum
public enum GrantDenyFlg {
	Y,
	N;

	GrantDenyFlg() {
	}

	public String value() {
		return name();
	}

	public static GrantDenyFlg fromValue(String v) {
		return valueOf(v);
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\cds\authZ\GrantDenyFlg.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */