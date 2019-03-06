package com.fedex.ea.framework.securityapi.dao.esc.cds.mapper;

import com.fedex.cds.CdsSecurityBase;
import com.fedex.ea.framework.securityapi.dao.esc.EscDaoException;

import javax.xml.bind.JAXBException;
import java.util.HashMap;
import java.util.Map;

public class CdsMapperCacheFactory
		extends CdsMapperFactory {
	private static final Map<CdsSecurityBase.STANZAS, CdsMapper> mapperMap = new HashMap();

	public CdsMapper createMapper(CdsSecurityBase.STANZAS stanza)
			throws JAXBException, EscDaoException {
		if (!mapperMap.containsKey(stanza)) {
			mapperMap.put(stanza, super.createMapper(stanza));
		}
		return mapperMap.get(stanza);
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\dao\esc\cds\mapper\CdsMapperCacheFactory.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */