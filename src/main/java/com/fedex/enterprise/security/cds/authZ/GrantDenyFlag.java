package com.fedex.enterprise.security.cds.authZ;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlType;

@XmlType(name = "Grant_Deny_Flag")
@XmlEnum
public enum GrantDenyFlag {
	Y,
	N;

	GrantDenyFlag() {
	}

	public String value() {
		return name();
	}

	public static GrantDenyFlag fromValue(String v) {
		return valueOf(v);
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\cds\authZ\GrantDenyFlag.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */