package com.fedex.ea.framework.securityapi.dao.esc.cds.mapper;

import com.fedex.enterprise.security.cds.authZ.ExtRuleXRef;
import com.fedex.enterprise.security.rule.ExtendedRuleXrefData;
import com.fedex.enterprise.security.utils.SecurityDataBaseClass;
import org.w3c.dom.Element;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

public class CdsExtRuleXRefMapper
		implements CdsMapper {
	private transient Unmarshaller unmarshaller = null;

	public CdsExtRuleXRefMapper() throws JAXBException {
		JAXBContext actionStanzaContext = null;
		actionStanzaContext = JAXBContext.newInstance(ExtRuleXRef.class);
		this.unmarshaller = actionStanzaContext.createUnmarshaller();
	}

	public SecurityDataBaseClass unmarshal(Element element) throws JAXBException {
		ExtRuleXRef currentXRef = (ExtRuleXRef)this.unmarshaller.unmarshal(element);
		ExtendedRuleXrefData newXRefData = new ExtendedRuleXrefData();
		newXRefData.setExtRuleDocId(currentXRef.getExtRuleDocId());
		newXRefData.setRuleDocId(currentXRef.getRuleDocId());
		newXRefData.setAppId(Long.toString(currentXRef.getApplicationId()));
		return newXRefData;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\dao\esc\cds\mapper\CdsExtRuleXRefMapper.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */