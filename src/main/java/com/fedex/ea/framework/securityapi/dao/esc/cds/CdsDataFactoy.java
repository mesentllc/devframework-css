package com.fedex.ea.framework.securityapi.dao.esc.cds;

import com.fedex.cds.CdsSecurityBase;
import com.fedex.ea.framework.securityapi.dao.esc.EscDaoException;
import com.fedex.enterprise.security.utils.SecurityDataBaseClass;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class CdsDataFactoy {
	private static final Map<CdsSecurityBase.STANZAS, Factory> FACTORY_MAP = Collections.unmodifiableMap(new HashMap() {
		private static final long serialVersionUID = 1L;
	});

	public static SecurityDataBaseClass createData(CdsSecurityBase.STANZAS stanza)
			throws EscDaoException {
		Factory factory = FACTORY_MAP.get(stanza);
		if (factory == null) {
			throw new EscDaoException("Unable to create Data, the CdsDataFactory class needs to be updated for " + stanza);
		}
		return factory.create();
	}

	private interface Factory {
		SecurityDataBaseClass create();
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\ea\framework\securityapi\dao\esc\cds\CdsDataFactoy.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */