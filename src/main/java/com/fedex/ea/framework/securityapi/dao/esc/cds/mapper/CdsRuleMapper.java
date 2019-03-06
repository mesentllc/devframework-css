package com.fedex.ea.framework.securityapi.dao.esc.cds.mapper;

import com.fedex.enterprise.security.cds.authZ.GrantDenyFlg;
import com.fedex.enterprise.security.cds.authZ.Rule;
import com.fedex.enterprise.security.rule.RuleData;
import com.fedex.enterprise.security.utils.SecurityDataBaseClass;
import org.w3c.dom.Element;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import java.util.ArrayList;

public class CdsRuleMapper
		implements CdsMapper {
	private transient Unmarshaller unmarshaller = null;

	public CdsRuleMapper() throws JAXBException {
		JAXBContext actionStanzaContext = null;
		actionStanzaContext = JAXBContext.newInstance(Rule.class);
		this.unmarshaller = actionStanzaContext.createUnmarshaller();
	}

	public SecurityDataBaseClass unmarshal(Element element) throws JAXBException {
		Rule currentRule = (Rule)this.unmarshaller.unmarshal(element);
		RuleData newRuleData = new RuleData();
		newRuleData.setActionDocId(currentRule.getActionDocId());
		newRuleData.setAppId(Long.toString(currentRule.getApplicationId()));
		newRuleData.setCustAuthZDocId(currentRule.getCustAuthZDocId());
		if (currentRule.getCustAuthZDocId() != 0L) {
			newRuleData.setCustAuthzExist(true);
		}
		if (currentRule.getGrantDenyFlg() == GrantDenyFlg.Y) {
			newRuleData.setGrantFlg('Y');
		}
		else {
			newRuleData.setGrantFlg('N');
		}
		newRuleData.setResDocId(currentRule.getResourceDocId());
		newRuleData.setRoleDocId(currentRule.getRoleDocId());
		newRuleData.setExtendedRuleList(new ArrayList());
		return newRuleData;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\dao\esc\cds\mapper\CdsRuleMapper.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */