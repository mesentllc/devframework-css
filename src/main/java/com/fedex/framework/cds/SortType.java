package com.fedex.framework.cds;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlType;

@XmlType(name = "sortType")
@XmlEnum
public enum SortType {
	ASC("asc"),
	DESC("desc");
	private final String value;

	SortType(String v) {
		this.value = v;
	}

	public String value() {
		return this.value;
	}

	public static SortType fromValue(String v) {
		for (SortType c : SortType.values()) {
			if (c.value.equals(v)) {
				return c;
			}
		}
		throw new IllegalArgumentException(v);
	}
}
