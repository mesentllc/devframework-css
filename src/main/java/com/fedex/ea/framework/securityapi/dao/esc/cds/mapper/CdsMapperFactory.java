package com.fedex.ea.framework.securityapi.dao.esc.cds.mapper;

import com.fedex.cds.CdsSecurityBase;
import com.fedex.ea.framework.securityapi.dao.esc.EscDaoException;

import javax.xml.bind.JAXBException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class CdsMapperFactory {
	private static final Map<CdsSecurityBase.STANZAS, Factory> FACTORY_MAP = Collections.unmodifiableMap(new HashMap() {
		private static final long serialVersionUID = 1L;
	});

	public CdsMapper createMapper(CdsSecurityBase.STANZAS stanza)
			throws JAXBException, EscDaoException {
		Factory factory = FACTORY_MAP.get(stanza);
		if (factory == null) {
			throw new EscDaoException("Unable to create mapper, the CdsMapperFactory class needs to be updated for " + stanza);
		}
		return factory.create();
	}

	private interface Factory {
		CdsMapper create()
				throws JAXBException;
	}
}
