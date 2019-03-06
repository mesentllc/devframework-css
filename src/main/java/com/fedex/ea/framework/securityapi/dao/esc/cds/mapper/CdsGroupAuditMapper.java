package com.fedex.ea.framework.securityapi.dao.esc.cds.mapper;

import com.fedex.enterprise.security.cds.authZ.Action;
import com.fedex.enterprise.security.group.audits.GroupAudit;
import com.fedex.enterprise.security.group.audits.GroupAuditData;
import org.w3c.dom.Element;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

public class CdsGroupAuditMapper implements CdsMapper {
	private transient Unmarshaller unmarshaller = null;

	public CdsGroupAuditMapper() throws JAXBException {
		JAXBContext stanzaContext = JAXBContext.newInstance(Action.class);
		this.unmarshaller = stanzaContext.createUnmarshaller();
	}

	public com.fedex.enterprise.security.utils.SecurityDataBaseClass unmarshal(Element element) throws JAXBException {
		GroupAudit groupAudit = (GroupAudit)this.unmarshaller.unmarshal(element);
		GroupAuditData groupAuditData = new GroupAuditData();
		groupAuditData.setChangedBy(groupAudit.getChangedBy());
		groupAuditData.setDateChanged(groupAudit.getDateChanged().toGregorianCalendar().getTime());
		groupAuditData.setEventDesc(groupAudit.getEventDesc());
		groupAuditData.setEventType(groupAudit.getEventType());
		groupAuditData.setGroupName(groupAudit.getGroupName());
		groupAuditData.setNewGroupFilter(groupAudit.getNewGroupFilter());
		groupAuditData.setNewGroupStaticMembers(groupAudit.getNewGroupStaticMembers());
		groupAuditData.setOldGroupFilter(groupAudit.getOldGroupFilter());
		groupAuditData.setOldGroupStaticMembers(groupAudit.getOldGroupStaticMembers());
		return groupAuditData;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\dao\esc\cds\mapper\CdsGroupAuditMapper.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */