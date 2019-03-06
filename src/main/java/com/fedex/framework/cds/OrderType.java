package com.fedex.framework.cds;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlType;

@XmlType(name = "orderType")
@XmlEnum
public enum OrderType {
	ASC("asc"),
	DESC("desc");
	private final String value;

	OrderType(String v) {
		this.value = v;
	}

	public String value() {
		return this.value;
	}

	public static OrderType fromValue(String v) {
		for (OrderType c : OrderType.values()) {
			if (c.value.equals(v)) {
				return c;
			}
		}
		throw new IllegalArgumentException(v);
	}
}
