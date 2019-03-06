package com.fedex.enterprise.security.resource;

public class Employee
		extends Person {
	private static final long serialVersionUID = 685927619703406876L;
	public static final String DEPARTMENT_NAME_COLUMN = "departmentName";
	public static final String SUB_DEPARTMENT_NAME_COLUMN = "subDepartmentName";
	public static final String ID_COLUMN = "employeeId";
	private String departmentName;
	private String subDepartmentName;
	protected int id;

	public Employee() {
	}

	public Employee(int id, String departmentName, String subDepartmentName, String firstName, String lastName, String phone) {
		super(firstName, lastName, phone);
		this.departmentName = departmentName;
		this.subDepartmentName = subDepartmentName;
		this.id = id;
	}

	public int getId() {
		return this.id;
	}

	public void setId(int id) {
		this.id = id;
	}

	public String getDepartmentName() {
		return this.departmentName;
	}

	public void setDepartmentName(String departmentName) {
		this.departmentName = departmentName;
	}

	public String getSubDepartmentName() {
		return this.subDepartmentName;
	}

	public void setSubDepartmentName(String subDepartmentName) {
		this.subDepartmentName = subDepartmentName;
	}

	public String toString() {
		return "[" + this.id + "," + this.firstName + "," + this.lastName + "]";
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\resource\Employee.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */