package com.fedex.ea.framework.securityapi.dao.esc.cds.mapper;

import com.fedex.enterprise.security.cds.authZ.GroupRole;
import com.fedex.enterprise.security.role.GroupRoleData;
import com.fedex.enterprise.security.utils.SecurityDataBaseClass;
import org.w3c.dom.Element;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

public class CdsGroupRoleMapper
		implements CdsMapper {
	private transient Unmarshaller unmarshaller = null;

	public CdsGroupRoleMapper() throws JAXBException {
		JAXBContext actionStanzaContext = null;
		actionStanzaContext = JAXBContext.newInstance(GroupRole.class);
		this.unmarshaller = actionStanzaContext.createUnmarshaller();
	}

	public SecurityDataBaseClass unmarshal(Element element) throws JAXBException {
		GroupRole currentGroupRole = (GroupRole)this.unmarshaller.unmarshal(element);
		GroupRoleData groupRoleData = new GroupRoleData();
		groupRoleData.setGroupNm(currentGroupRole.getGroupName());
		groupRoleData.setRoleDocId(currentGroupRole.getRoleDocId());
		groupRoleData.setAssignedBy(currentGroupRole.getAssignedBy());
		if (currentGroupRole.getDateAssigned() != null) {
			groupRoleData.setDateAssigned(currentGroupRole.getDateAssigned().toGregorianCalendar());
		}
		return groupRoleData;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\dao\esc\cds\mapper\CdsGroupRoleMapper.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */