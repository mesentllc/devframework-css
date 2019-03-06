package com.fedex.ea.framework.securityapi.dao.esc.cds.mapper;

import com.fedex.enterprise.security.role.restriction.Entry;
import com.fedex.enterprise.security.role.restriction.RestrictionData;
import com.fedex.enterprise.security.role.restriction.RestrictionDataItem;
import com.fedex.enterprise.security.utils.SecurityDataBaseClass;
import com.fedex.xmlns.cds.authz.Restriction;
import org.w3c.dom.Element;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import java.util.ArrayList;
import java.util.List;

public class CdsRestrictionMapper
		implements CdsMapper {
	private transient Unmarshaller unmarshaller = null;

	public CdsRestrictionMapper() throws JAXBException {
		JAXBContext actionStanzaContext = null;
		actionStanzaContext = JAXBContext.newInstance(Restriction.class);
		this.unmarshaller = actionStanzaContext.createUnmarshaller();
	}

	public SecurityDataBaseClass unmarshal(Element element) throws JAXBException {
		Restriction currentRestriction = (Restriction)this.unmarshaller.unmarshal(element);
		RestrictionData restrictionData = new RestrictionData();
		restrictionData.setRoleDocId(currentRestriction.getROLEDOCID());
		restrictionData.setRoleNm(currentRestriction.getROLENAME());
		if (currentRestriction.getUSERID().getEmployeeId() != null) {
			restrictionData.setEmplId(currentRestriction.getUSERID().getEmployeeId());
		}
		if (currentRestriction.getUSERID().getGroupName() != null) {
			restrictionData.setGroupNm(currentRestriction.getUSERID().getGroupName());
		}
		restrictionData.setAppId(Long.toString(currentRestriction.getAPPID()));
		List<RestrictionDataItem> resItemList = new ArrayList();
		for (Restriction.RestrictionItem referenceData : currentRestriction.getRestrictionItem()) {
			RestrictionDataItem resDataItem = new RestrictionDataItem();
			List<Entry> itemList = new ArrayList();
			for (Restriction.RestrictionItem.Entry entry : referenceData.getEntry()) {
				Entry newEntry = new Entry();
				newEntry.setKey(entry.getKey());
				newEntry.setValue(entry.getValue());
				itemList.add(newEntry);
			}
			resDataItem.setRestrictionItemIndex(referenceData.getRestrictionDataItemIndex());
			resDataItem.setEntryList(itemList);
			resItemList.add(resDataItem);
		}
		restrictionData.setRestrictionList(resItemList);
		return restrictionData;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\dao\esc\cds\mapper\CdsRestrictionMapper.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */