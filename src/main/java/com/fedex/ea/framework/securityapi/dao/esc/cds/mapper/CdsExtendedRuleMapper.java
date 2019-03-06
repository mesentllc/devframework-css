package com.fedex.ea.framework.securityapi.dao.esc.cds.mapper;

import com.fedex.enterprise.security.cds.authZ.ExtendedRule;
import com.fedex.enterprise.security.rule.ExtendedRuleData;
import com.fedex.enterprise.security.utils.SecurityDataBaseClass;
import org.w3c.dom.Element;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

public class CdsExtendedRuleMapper
		implements CdsMapper {
	private transient Unmarshaller unmarshaller = null;

	public CdsExtendedRuleMapper() throws JAXBException {
		JAXBContext actionStanzaContext = null;
		actionStanzaContext = JAXBContext.newInstance(ExtendedRule.class);
		this.unmarshaller = actionStanzaContext.createUnmarshaller();
	}

	public SecurityDataBaseClass unmarshal(Element element) throws JAXBException {
		ExtendedRule currentRule = (ExtendedRule)this.unmarshaller.unmarshal(element);
		ExtendedRuleData newExtendedRuleData = new ExtendedRuleData();
		newExtendedRuleData.setAppId(Long.toString(currentRule.getApplicationId()));
		newExtendedRuleData.setExtRuleKey(currentRule.getExtendedRuleKey());
		newExtendedRuleData.setExtRuleOperator(currentRule.getExtendedRuleOperator());
		newExtendedRuleData.setExtRuleType(currentRule.getExtendedRuleValueType());
		newExtendedRuleData.setExtRuleValue(currentRule.getExtendedRuleValue());
		return newExtendedRuleData;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\dao\esc\cds\mapper\CdsExtendedRuleMapper.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */