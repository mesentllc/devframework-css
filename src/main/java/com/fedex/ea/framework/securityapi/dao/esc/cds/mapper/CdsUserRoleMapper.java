package com.fedex.ea.framework.securityapi.dao.esc.cds.mapper;

import com.fedex.enterprise.security.cds.authZ.UserRole;
import com.fedex.enterprise.security.role.UserRoleData;
import com.fedex.enterprise.security.utils.SecurityDataBaseClass;
import org.w3c.dom.Element;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

public class CdsUserRoleMapper
		implements CdsMapper {
	private transient Unmarshaller unmarshaller = null;

	public CdsUserRoleMapper() throws JAXBException {
		JAXBContext actionStanzaContext = null;
		actionStanzaContext = JAXBContext.newInstance(UserRole.class);
		this.unmarshaller = actionStanzaContext.createUnmarshaller();
	}

	public SecurityDataBaseClass unmarshal(Element element) throws JAXBException {
		UserRole currentUserRole = (UserRole)this.unmarshaller.unmarshal(element);
		UserRoleData userRoleData = new UserRoleData();
		userRoleData.setEmpNbr(currentUserRole.getUserFedExId());
		userRoleData.setRoleDocId(currentUserRole.getRoleDocId());
		userRoleData.setAssignedBy(currentUserRole.getAssignedBy());
		if (currentUserRole.getDateAssigned() != null) {
			userRoleData.setDateAssigned(currentUserRole.getDateAssigned().toGregorianCalendar());
		}
		return userRoleData;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\dao\esc\cds\mapper\CdsUserRoleMapper.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */