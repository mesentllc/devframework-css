package com.fedex.framework.cds;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlType;

@XmlType(name = "effectiveDateFilterType")
@XmlEnum
public enum EffectiveDateFilterType {
	HISTORY("history"),
	CURRENT("current"),
	FUTURE("future");
	private final String value;

	EffectiveDateFilterType(String v) {
		this.value = v;
	}

	public String value() {
		return this.value;
	}

	public static EffectiveDateFilterType fromValue(String v) {
		for (EffectiveDateFilterType c : EffectiveDateFilterType.values()) {
			if (c.value.equals(v)) {
				return c;
			}
		}
		throw new IllegalArgumentException(v);
	}
}
