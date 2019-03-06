package com.fedex.ea.framework.securityapi.dao.esc.cds.mapper;

import com.fedex.enterprise.security.cds.authZ.ApplicationRole;
import com.fedex.enterprise.security.role.AppRoleData;
import com.fedex.enterprise.security.utils.SecurityDataBaseClass;
import org.w3c.dom.Element;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

public class CdsAppRoleMapper
		implements CdsMapper {
	private transient Unmarshaller unmarshaller = null;

	public CdsAppRoleMapper() throws JAXBException {
		JAXBContext actionStanzaContext = null;
		actionStanzaContext = JAXBContext.newInstance(ApplicationRole.class);
		this.unmarshaller = actionStanzaContext.createUnmarshaller();
	}

	public SecurityDataBaseClass unmarshal(Element element) throws JAXBException {
		ApplicationRole currentAppRole = (ApplicationRole)this.unmarshaller.unmarshal(element);
		AppRoleData appRoleData = new AppRoleData();
		appRoleData.setAppId(Long.toString(currentAppRole.getApplicationId()));
		appRoleData.setAssignedBy(currentAppRole.getAssignedBy());
		if (currentAppRole.getDateAssigned() != null) {
			appRoleData.setDateAssigned(currentAppRole.getDateAssigned().toGregorianCalendar());
		}
		appRoleData.setRoleDocId(currentAppRole.getRoleDocId());
		return appRoleData;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\dao\esc\cds\mapper\CdsAppRoleMapper.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */