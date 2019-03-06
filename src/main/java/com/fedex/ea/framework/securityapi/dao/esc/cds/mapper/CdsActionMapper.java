package com.fedex.ea.framework.securityapi.dao.esc.cds.mapper;

import com.fedex.enterprise.security.action.ActionData;
import com.fedex.enterprise.security.cds.authZ.Action;
import com.fedex.enterprise.security.utils.SecurityDataBaseClass;
import org.w3c.dom.Element;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

public class CdsActionMapper
		implements CdsMapper {
	private transient Unmarshaller unmarshaller = null;

	public CdsActionMapper() throws JAXBException {
		JAXBContext actionStanzaContext = null;
		actionStanzaContext = JAXBContext.newInstance(Action.class);
		this.unmarshaller = actionStanzaContext.createUnmarshaller();
	}

	public SecurityDataBaseClass unmarshal(Element element) throws JAXBException {
		Action action = (Action)this.unmarshaller.unmarshal(element);
		ActionData actionData = new ActionData();
		actionData.setAppId(String.valueOf(action.getApplicationId()));
		actionData.setActionDesc(action.getActionDesc());
		actionData.setActionNm(action.getActionName());
		return actionData;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\dao\esc\cds\mapper\CdsActionMapper.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */