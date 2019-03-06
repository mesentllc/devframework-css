package com.fedex.ea.framework.securityapi.dao.esc.cds.mapper;

import com.fedex.enterprise.security.cds.authZ.Resource;
import com.fedex.enterprise.security.resource.ResourceData;
import com.fedex.enterprise.security.utils.SecurityDataBaseClass;
import org.w3c.dom.Element;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

public class CdsResourceMapper
		implements CdsMapper {
	private transient Unmarshaller unmarshaller = null;

	public CdsResourceMapper() throws JAXBException {
		JAXBContext actionStanzaContext = null;
		actionStanzaContext = JAXBContext.newInstance(Resource.class);
		this.unmarshaller = actionStanzaContext.createUnmarshaller();
	}

	public SecurityDataBaseClass unmarshal(Element element) throws JAXBException {
		Resource currentResource = (Resource)this.unmarshaller.unmarshal(element);
		ResourceData newResourceData = new ResourceData();
		newResourceData.setResDesc(currentResource.getResourceDesc());
		newResourceData.setResName(currentResource.getResourceName());
		newResourceData.setAppId(Long.toString(currentResource.getApplicationId()));
		newResourceData.setRootFlg(currentResource.getRootFlg().charAt(0));
		return newResourceData;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\dao\esc\cds\mapper\CdsResourceMapper.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */