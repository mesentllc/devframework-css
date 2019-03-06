package com.fedex.ea.framework.securityapi.dao.esc.cds.mapper;

import com.fedex.enterprise.security.cds.authZ.Role;
import com.fedex.enterprise.security.role.RoleData;
import com.fedex.enterprise.security.utils.SecurityDataBaseClass;
import org.w3c.dom.Element;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

public class CdsRoleMapper
		implements CdsMapper {
	private transient Unmarshaller unmarshaller = null;

	public CdsRoleMapper() throws JAXBException {
		JAXBContext actionStanzaContext = null;
		actionStanzaContext = JAXBContext.newInstance(Role.class);
		this.unmarshaller = actionStanzaContext.createUnmarshaller();
	}

	public SecurityDataBaseClass unmarshal(Element element) throws JAXBException {
		Role currentRole = (Role)this.unmarshaller.unmarshal(element);
		RoleData roleData = new RoleData();
		roleData.setRoleDesc(currentRole.getRoleDesc());
		roleData.setRoleNm(currentRole.getRoleName());
		roleData.setRoleScopeNm(currentRole.getRoleScopeName());
		roleData.setRoleTypeCd(currentRole.getRoleScopeType());
		roleData.setAppId(currentRole.getRoleScopeName());
		return roleData;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\dao\esc\cds\mapper\CdsRoleMapper.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */