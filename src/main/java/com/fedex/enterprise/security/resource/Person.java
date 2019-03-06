package com.fedex.enterprise.security.resource;

import java.io.Serializable;

public class Person
		implements Serializable {
	private static final long serialVersionUID = 8597042206269069531L;
	public static final String LAST_NAME_COLUMN = "lastName";
	public static final String FIRST_NAME_COLUMN = "firstName";
	public static final String PHONE_COLUMN = "phone";
	protected String lastName;
	protected String firstName;
	protected String phone;
	protected boolean selected;

	public Person() {
	}

	public Person(String firstName, String lastName, String phone) {
		this.firstName = firstName;
		this.lastName = lastName;
		this.phone = phone;
	}

	public String getLastName() {
		return this.lastName;
	}

	public void setLastName(String lastName) {
		this.lastName = lastName;
	}

	public String getFirstName() {
		return this.firstName;
	}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}

	public String getPhone() {
		return this.phone;
	}

	public void setPhone(String phone) {
		this.phone = phone;
	}

	public boolean isSelected() {
		return this.selected;
	}

	public void setSelected(boolean selected) {
		this.selected = selected;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\resource\Person.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */