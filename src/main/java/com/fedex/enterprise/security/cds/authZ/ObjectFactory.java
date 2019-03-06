package com.fedex.enterprise.security.cds.authZ;

import javax.xml.bind.annotation.XmlRegistry;

@XmlRegistry
public class ObjectFactory {
	public Rule createRule() {
		return new Rule();
	}

	public GroupRole createGroupRole() {
		return new GroupRole();
	}

	public RoleOwner createRoleOwner() {
		return new RoleOwner();
	}

	public CustomAuthZClass createCustomAuthZClass() {
		return new CustomAuthZClass();
	}

	public GroupOwner createGroupOwner() {
		return new GroupOwner();
	}

	public Action createAction() {
		return new Action();
	}

	public UserRole createUserRole() {
		return new UserRole();
	}

	public ExtendedRule createExtendedRule() {
		return new ExtendedRule();
	}

	public ExtRuleXRef createExtRuleXRef() {
		return new ExtRuleXRef();
	}

	public Resource createResource() {
		return new Resource();
	}

	public AuditRecord createAuditRecord() {
		return new AuditRecord();
	}

	public Role createRole() {
		return new Role();
	}

	public ApplicationRole createApplicationRole() {
		return new ApplicationRole();
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\cds\authZ\ObjectFactory.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */