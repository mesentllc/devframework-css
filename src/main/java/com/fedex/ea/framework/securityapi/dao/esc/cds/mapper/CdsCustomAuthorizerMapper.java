package com.fedex.ea.framework.securityapi.dao.esc.cds.mapper;

import com.fedex.enterprise.security.cds.authZ.CustomAuthZClass;
import com.fedex.enterprise.security.customauthz.CustomAuthzData;
import com.fedex.enterprise.security.utils.SecurityDataBaseClass;
import org.w3c.dom.Element;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

public class CdsCustomAuthorizerMapper
		implements CdsMapper {
	private transient Unmarshaller unmarshaller = null;

	public CdsCustomAuthorizerMapper() throws JAXBException {
		JAXBContext actionStanzaContext = null;
		actionStanzaContext = JAXBContext.newInstance(CustomAuthZClass.class);
		this.unmarshaller = actionStanzaContext.createUnmarshaller();
	}

	public SecurityDataBaseClass unmarshal(Element element) throws JAXBException {
		CustomAuthZClass currentCustomAuthZ = (CustomAuthZClass)this.unmarshaller.unmarshal(element);
		CustomAuthzData customAuthz = new CustomAuthzData();
		customAuthz.setClassNm(currentCustomAuthZ.getCustomAuthZClassName());
		customAuthz.setClassDesc(currentCustomAuthZ.getCustomAuthZClassDesc());
		customAuthz.setAppId(String.valueOf(currentCustomAuthZ.getApplicationId()));
		return customAuthz;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\dao\esc\cds\mapper\CdsCustomAuthorizerMapper.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */