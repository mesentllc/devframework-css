package com.fedex.ea.framework.securityapi.dao.esc.cds.mapper;

import com.fedex.enterprise.security.utils.SecurityDataBaseClass;
import org.w3c.dom.Element;

import javax.xml.bind.JAXBException;

public interface CdsMapper {
	SecurityDataBaseClass unmarshal(Element paramElement)
			throws JAXBException;
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\dao\esc\cds\mapper\CdsMapper.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */